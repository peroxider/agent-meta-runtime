"""Step 03 capability-surface tests: deterministic surface artifacts, the
§41.59.1 cache key / fingerprint, authority filtering, and accept-time
resolution (FR-MCAP, AC-M29/M38)."""

from __future__ import annotations

import json

from agent_meta_runtime.adapters.store import (
    CompositionCreateRequest,
    CreateGrantRequest,
    RootBootstrapRequest,
    TaskAcceptRequest,
    accept_task,
    bootstrap_root,
    create_composition,
    create_grant,
)
from agent_meta_runtime.adapters.store.semantic import TaskBudget
from agent_meta_runtime.domain.authority import GrantConstraints, Scope, ScopeTarget
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.surface import (
    GrantProjectionEntry,
    SurfaceOperation,
    authority_fingerprint,
    build_surface_artifact,
)

from conftest import ACTOR, artifact_id, run_command, _seed_artifact

REALM = "realm://main"
OTHER_ACTOR = "principal://agent/01900000-0000-7000-8000-000000000001"


def _op(operation_id, permissions=()):
    return SurfaceOperation(
        operation_id=operation_id,
        contract_version="1.0.0",
        input_schema_hash="ih",
        output_schema_hash="oh",
        description="d",
        effects=("state.read",),
        idempotency="KEYED",
        retry_semantics="SAME_KEY_TRANSIENT",
        required_permissions=tuple(sorted(permissions)),
        scope={"realm_id": REALM, "targets": []},
        availability_reason="READY",
    )


def _projection_entry(grant_id="grant://g", permission="state.read"):
    return GrantProjectionEntry(
        grant_id=grant_id,
        permission=permission,
        canonical_scope='{"realm_id":"realm://main","targets":[{"id":"*","type":"REALM_ALL"}]}',
        not_before_us=None,
        expires_at_us=None,
        remaining_uses=None,
    )


def _finger(**overrides):
    args = dict(
        principal_id=OTHER_ACTOR,
        epoch_id="epoch://e-1",
        authority_history_boundary_meta_revision=3,
        grant_projection=[_projection_entry()],
    )
    args.update(overrides)
    return authority_fingerprint(**args)


def test_surface_artifact_is_deterministic_and_sorted():
    body_a, id_a = build_surface_artifact([_op("beta"), _op("alpha")])
    body_b, id_b = build_surface_artifact([_op("alpha"), _op("beta")])
    assert id_a == id_b
    assert body_a == body_b
    ids = [op["operation_id"] for op in json.loads(bytes(body_a))["operations"]]
    assert ids == ["alpha", "beta"]


def test_fingerprint_discriminates_authority_state():
    base = _finger()
    assert base == _finger()
    # A grant-history boundary move changes the key.
    assert base != _finger(authority_history_boundary_meta_revision=4)
    # A different projection changes the key.
    assert base != _finger(grant_projection=[_projection_entry(permission="state.write")])
    assert base != _finger(grant_projection=[])
    # Same projection content, different construction order, same hash.
    assert _finger(
        grant_projection=[
            _projection_entry(grant_id="grant://a"),
            _projection_entry(grant_id="grant://b"),
        ]
    ) == _finger(
        grant_projection=[
            _projection_entry(grant_id="grant://b"),
            _projection_entry(grant_id="grant://a"),
        ]
    )
    # A different principal or epoch changes the key.
    assert base != _finger(principal_id=ACTOR)
    assert base != _finger(epoch_id="epoch://e-2")


def _env(store):
    """Realm with root principal, one capability, one composition revision."""

    conn, realm, _tmp = store
    run_command(
        conn,
        bootstrap_root(
            RootBootstrapRequest(
                realm_id=realm,
                epoch_id="epoch://e-surf",
                principal_id=ACTOR,
                public_key=b"\x01" * 32,
                recovery_code_hash="a" * 64,
            )
        ),
    )
    input_art = artifact_id("input")
    cap_art = artifact_id("cap")
    _seed_artifact(conn, input_art)
    _seed_artifact(conn, cap_art)
    descriptor = {
        "capability_id": "capability://cap-x",
        "contract_version": "1.0.0",
        "operations": [
            {
                "operation_id": "op_pub",
                "description": "public",
                "effects": ["state.read"],
                "idempotency": "KEYED",
                "retry_semantics": "SAME_KEY_TRANSIENT",
                "required_permissions": [],
            },
            {
                "operation_id": "op_protected",
                "description": "protected",
                "effects": ["state.write"],
                "idempotency": "NONE",
                "retry_semantics": "NEVER",
                "required_permissions": ["state.write"],
            },
        ],
    }
    conn.execute(
        "INSERT INTO capabilities(capability_id, descriptor_revision, artifact_id,"
        " descriptor_json, created_at_us) VALUES (?, 1, ?, ?, 1)",
        ("capability://cap-x", cap_art, canonical_json(descriptor)),
    )
    body = {
        "schema": "composition/v1",
        "realm_id": realm,
        "slots": {
            "alpha": {"capability_id": "capability://cap-x", "descriptor_revision": 1}
        },
    }
    composition = run_command(
        conn,
        create_composition(
            CompositionCreateRequest(realm_id=realm, body=body, created_by=ACTOR, revision=1)
        ),
    )["composition_id"]
    conn.commit()
    return conn, realm, composition, input_art


def _accept(conn, composition_id, input_art, actor=ACTOR):
    return run_command(
        conn,
        accept_task(
            TaskAcceptRequest(
                task_id=None,
                actor_id=actor,
                input_artifact_id=input_art,
                serving_composition_id=composition_id,
                serving_revision=1,
                budget=TaskBudget(),
            )
        ),
    )


def _surfaces(conn, realm):
    return conn.execute(
        "SELECT surface_revision, artifact_id, authority_fingerprint"
        " FROM capability_surfaces WHERE realm_id = ? ORDER BY surface_revision",
        (realm,),
    ).fetchall()


def test_accept_resolves_then_reuses_surface(store):
    conn, realm, composition, input_art = _env(store)
    first = _accept(conn, composition, input_art)
    second = _accept(conn, composition, input_art)
    rows = _surfaces(conn, realm)
    assert len(rows) == 1
    assert rows[0][0] == 1
    for task_id in (first["task_id"], second["task_id"]):
        surface = conn.execute(
            "SELECT capability_surface_revision, capability_surface_artifact_id"
            " FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        assert surface[0] == 1
        assert surface[1] == rows[0][1]
    # The surface artifact is registered in the artifact store.
    assert conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?", (rows[0][1],)
    ).fetchone()[0] == 1


def test_replaced_capability_keeps_history_resolvable(store):
    conn, realm, composition, input_art = _env(store)
    first = _accept(conn, composition, input_art)
    old_surface = conn.execute(
        "SELECT capability_surface_artifact_id FROM tasks WHERE task_id = ?",
        (first["task_id"],),
    ).fetchone()[0]
    old_descriptor = conn.execute(
        "SELECT descriptor_json FROM capabilities WHERE capability_id = ?"
        " AND descriptor_revision = 1",
        ("capability://cap-x",),
    ).fetchone()[0]
    # The capability is replaced by a new descriptor revision; the old row
    # is never mutated or removed.
    cap_art_2 = artifact_id("cap-2")
    _seed_artifact(conn, cap_art_2)
    new_descriptor = {
        "capability_id": "capability://cap-x",
        "contract_version": "2.0.0",
        "operations": [
            {
                "operation_id": "op_new",
                "description": "replacement",
                "effects": ["state.read"],
                "idempotency": "KEYED",
                "retry_semantics": "SAME_KEY_TRANSIENT",
                "required_permissions": [],
            }
        ],
    }
    conn.execute(
        "INSERT INTO capabilities(capability_id, descriptor_revision, artifact_id,"
        " descriptor_json, created_at_us) VALUES (?, 2, ?, ?, 1)",
        ("capability://cap-x", cap_art_2, canonical_json(new_descriptor)),
    )
    conn.commit()
    # History still resolves: the old descriptor revision and the accepted
    # task's surface artifact remain intact and addressable.
    assert conn.execute(
        "SELECT descriptor_json FROM capabilities WHERE capability_id = ?"
        " AND descriptor_revision = 1",
        ("capability://cap-x",),
    ).fetchone()[0] == old_descriptor
    assert conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?", (old_surface,)
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT capability_surface_artifact_id FROM tasks WHERE task_id = ?",
        (first["task_id"],),
    ).fetchone()[0] == old_surface


def test_authority_state_selects_the_surface(store):
    conn, realm, composition, input_art = _env(store)
    # Root (all permissions): its own surface row.
    _accept(conn, composition, input_art, actor=ACTOR)
    root_rows = _surfaces(conn, realm)
    assert len(root_rows) == 1
    # Another principal with no grants: new fingerprint, new revision.
    _accept(conn, composition, input_art, actor=OTHER_ACTOR)
    rows = _surfaces(conn, realm)
    assert len(rows) == 2
    assert rows[1][2] != rows[0][2]
    # Delegating state.write moves the boundary and the projection again.
    root_grant_id = conn.execute(
        "SELECT grant_id FROM authority_grants WHERE subject_id = ?", (ACTOR,)
    ).fetchone()[0]
    run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=OTHER_ACTOR,
                permissions={"state.write"},
                scope=Scope(realm_id=realm, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(),
            )
        ),
    )
    _accept(conn, composition, input_art, actor=OTHER_ACTOR)
    rows_after = _surfaces(conn, realm)
    assert len(rows_after) == 3
    assert rows_after[2][2] not in (rows[0][2], rows[1][2])
    # Every task row points at the surface revision chosen at its accept time.
    revisions = [
        r[0]
        for r in conn.execute(
            "SELECT capability_surface_revision FROM tasks ORDER BY accepted_at_us"
        ).fetchall()
    ]
    assert revisions == [1, 2, 3]
