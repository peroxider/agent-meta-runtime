"""Step 03 authority tests: scope matching, delegation containment, revoke /
expire / exhaustion semantics, signature preimages, root bootstrap (§41.28,
§41.31, FR-MAUTH, AC-M05/M21/M25)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import (
    CreateGrantRequest,
    ReserveAuthorityUseRequest,
    RevokeGrantRequest,
    RootBootstrapRequest,
    bootstrap_root,
    create_grant,
    reserve_authority_use,
    revoke_grant,
)
from agent_meta_runtime.domain.authority import (
    PERMISSIONS,
    Grant,
    GrantConstraints,
    Scope,
    ScopeTarget,
    authorize,
    command_signature_preimage,
    execution_token_payload_hash,
    validate_delegation,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError

from conftest import ACTOR, execute_command_result, run_command

REALM = "realm://main"
OTHER_ACTOR = "principal://agent/01900000-0000-7000-8000-000000000001"


def _grant(**overrides):
    defaults = dict(
        grant_id="grant://g-parent",
        epoch_id="epoch://e-bb",
        issuer_id="grant://root",
        subject_id=OTHER_ACTOR,
        delegation_depth=2,
        permissions=frozenset({"task.submit", "state.read"}),
        scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
        constraints=GrantConstraints(),
        delegable=True,
        status="ACTIVE",
        issued_at_us=0,
    )
    defaults.update(overrides)
    return Grant(**defaults)


def _bootstrap(conn) -> str:
    receipt = run_command(
        conn,
        bootstrap_root(
            RootBootstrapRequest(
                realm_id=REALM,
                epoch_id="epoch://e-cc",
                principal_id=ACTOR,
                public_key=b"\x01" * 32,
                recovery_code_hash="a" * 64,
            )
        ),
    )
    return receipt["grant_id"]


def test_unknown_permission_fails_closed():
    with pytest.raises(StableError) as excinfo:
        Grant(
            grant_id="grant://g",
            epoch_id="epoch://e",
            issuer_id="grant://root",
            subject_id=OTHER_ACTOR,
            delegation_depth=1,
            permissions=frozenset({"task.submit", "galaxy.warp"}),
            scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
            constraints=GrantConstraints(),
            delegable=True,
            status="ACTIVE",
            issued_at_us=0,
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT
    # The fixed registry holds exactly the 42 spec names.
    assert len(PERMISSIONS) == 42
    assert "task.submit" in PERMISSIONS
    assert "effect.execute.irreversible" in PERMISSIONS


def test_authorization_order_and_denial_reasons():
    base = dict(
        subject_id=OTHER_ACTOR,
        permission="task.submit",
        resource_realm=REALM,
        resource_target=None,
        now_us=10_000,
    )
    # STATUS (revoked) fires before anything else — including subject mismatch.
    assert (
        authorize(_grant(status="REVOKED"), epoch_id="epoch://e-bb", **base)
        == "STATUS"
    )
    assert (
        authorize(
            _grant(status="REVOKED", subject_id=ACTOR),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "STATUS"
    )
    # SUBJECT before PERMISSION.
    assert (
        authorize(_grant(subject_id=ACTOR), epoch_id="epoch://e-bb", **base)
        == "SUBJECT"
    )
    # PERMISSION before SCOPE.
    assert (
        authorize(
            _grant(permissions=frozenset({"state.read"})),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "PERMISSION"
    )
    # SCOPE before constraint time.
    assert (
        authorize(
            _grant(
                scope=Scope(
                    realm_id=REALM,
                    targets=[ScopeTarget(type="TASK", id="task://t-scope")],
                )
            ),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "SCOPE"
    )
    # CONSTRAINT_TIME (not_before in the future).
    assert (
        authorize(
            _grant(constraints=GrantConstraints(not_before_us=20_000)),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "CONSTRAINT_TIME"
    )
    # EPOCH (constraint-bound grant used in another epoch).
    assert (
        authorize(
            _grant(constraints=GrantConstraints(epoch_id="epoch://e-xx")),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "EPOCH"
    )


def test_scope_typed_union_matching():
    grant = _grant(
        scope=Scope(
            realm_id=REALM,
            targets=[
                ScopeTarget(type="CAPABILITY", id="capability://cap-a"),
                ScopeTarget(type="ARTIFACT_KIND", id="dataset"),
            ],
        )
    )
    base = dict(
        subject_id=OTHER_ACTOR,
        permission="task.submit",
        resource_realm=REALM,
        now_us=10_000,
    )
    assert (
        authorize(
            grant,
            resource_target=ScopeTarget(type="CAPABILITY", id="capability://cap-a"),
            epoch_id="epoch://e-bb",
            **base,
        )
        is None
    )
    assert (
        authorize(
            grant,
            resource_target=ScopeTarget(type="ARTIFACT_KIND", id="dataset"),
            epoch_id="epoch://e-bb",
            **base,
        )
        is None
    )
    assert (
        authorize(
            grant,
            resource_target=ScopeTarget(type="CAPABILITY", id="capability://cap-b"),
            epoch_id="epoch://e-bb",
            **base,
        )
        == "SCOPE"
    )


def test_delegation_containment_never_expands():
    parent = _grant()
    # Equal containment is fine and decrements depth.
    assert (
        validate_delegation(
            parent,
            child_permissions=parent.permissions,
            child_scope=parent.scope,
            child_constraints=GrantConstraints(),
            child_delegable=True,
        )
        == 1
    )
    # Expanded permissions are denied.
    with pytest.raises(StableError) as excinfo:
        validate_delegation(
            parent,
            child_permissions=frozenset(
                {"task.submit", "state.read", "state.write"}
            ),
            child_scope=parent.scope,
            child_constraints=GrantConstraints(),
            child_delegable=True,
        )
    assert excinfo.value.code == ErrorCode.AUTHORITY_DENIED
    # Unbounded child constraints are denied even when the parent is bounded.
    with pytest.raises(StableError) as excinfo:
        validate_delegation(
            parent,
            child_permissions=parent.permissions,
            child_scope=parent.scope,
            child_constraints=GrantConstraints(unbounded=True),
            child_delegable=True,
        )
    assert excinfo.value.code == ErrorCode.AUTHORITY_DENIED
    # A delegable child needs one depth level to spare.
    shallow = _grant(delegation_depth=1)
    with pytest.raises(StableError) as excinfo:
        validate_delegation(
            shallow,
            child_permissions=shallow.permissions,
            child_scope=shallow.scope,
            child_constraints=GrantConstraints(),
            child_delegable=True,
        )
    assert excinfo.value.code == ErrorCode.AUTHORITY_DENIED
    # Depth exhausted.
    exhausted = _grant(delegation_depth=0)
    with pytest.raises(StableError) as excinfo:
        validate_delegation(
            exhausted,
            child_permissions=exhausted.permissions,
            child_scope=exhausted.scope,
            child_constraints=GrantConstraints(),
            child_delegable=True,
        )
    assert excinfo.value.code == ErrorCode.AUTHORITY_DENIED


def test_signature_preimages_are_stable():
    preimage = command_signature_preimage(
        authorization_hash="ab" * 32, nonce="nonce-1", issued_at_us=1_234_567
    )
    assert preimage.startswith(b"agent-meta-command-v1\x00")
    assert b"nonce-1" in preimage
    again = command_signature_preimage(
        authorization_hash="ab" * 32, nonce="nonce-1", issued_at_us=1_234_567
    )
    assert preimage == again
    with pytest.raises(ValueError):
        command_signature_preimage(
            authorization_hash="ab" * 31, nonce="n", issued_at_us=1
        )
    # Token payload hash: fixed 12-field JCS payload.
    payload = {
        "token_version": 1,
        "token_id": "token://t",
        "backend_session_id": "session://s",
        "realm_id": REALM,
        "actor_id": OTHER_ACTOR,
        "action_id": "action://a",
        "effect_kind": "artifact.put",
        "target_scope_hash": "tsh",
        "resource_ceiling": {},
        "issued_at_us": 1,
        "expires_at_us": 2,
        "nonce": "n",
    }
    h1 = execution_token_payload_hash(payload)
    h2 = execution_token_payload_hash(dict(reversed(list(payload.items()))))
    assert h1 == h2
    with pytest.raises(ValueError):
        execution_token_payload_hash(
            {k: v for k, v in payload.items() if k != "nonce"}
        )


def test_bootstrap_root_and_repeat_init_refused(store):
    conn, _realm, _tmp = store
    root_grant_id = _bootstrap(conn)
    assert root_grant_id.startswith("grant://")
    epoch_row = conn.execute(
        "SELECT epoch_id, ordinal FROM epochs WHERE realm_id = ?", (REALM,)
    ).fetchone()
    assert epoch_row[0] == "epoch://e-cc"
    principal_row = conn.execute(
        "SELECT kind, public_identity_json FROM principals WHERE principal_id = ?",
        (ACTOR,),
    ).fetchone()
    assert principal_row[0] == "OPERATOR_ROOT"
    grant_row = conn.execute(
        "SELECT status, permissions_json FROM authority_grants WHERE grant_id = ?",
        (root_grant_id,),
    ).fetchone()
    assert grant_row[0] == "ACTIVE"
    assert "task.submit" in bytes(grant_row[1]).decode("utf-8")
    recovery_row = conn.execute(
        "SELECT generation FROM root_recovery WHERE realm_id = ?", (REALM,)
    ).fetchone()
    assert recovery_row[0] == 1
    # Repeat init with the same root principal is refused.
    result = execute_command_result(
        conn,
        bootstrap_root(
            RootBootstrapRequest(
                realm_id=REALM,
                epoch_id="epoch://e-cc",
                principal_id=ACTOR,
                public_key=b"\x01" * 32,
                recovery_code_hash="a" * 64,
            )
        ),
    )
    assert result.error is not None
    assert result.error.code == "ALREADY_EXISTS"


def test_delegate_then_revoke_immediately_denies_new_calls(store):
    conn, _realm, _tmp = store
    root_grant_id = _bootstrap(conn)
    child = run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=OTHER_ACTOR,
                permissions={"task.submit", "state.read"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(delegation_depth_remaining=3),
            )
        ),
    )
    child_grant_id = child["grant_id"]
    assert child["delegation_depth"] == 3
    use = run_command(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-1",
            )
        ),
    )
    assert use["uses_count"] == 1
    # Replay of the identical use does not double-charge.
    replay = run_command(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-1",
            )
        ),
    )
    assert replay["uses_count"] == 1
    run_command(conn, revoke_grant(RevokeGrantRequest(grant_id=child_grant_id)))
    # Revocation hits the very next call.
    result = execute_command_result(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-2",
            )
        ),
    )
    assert result.error is not None
    assert result.error.code == "AUTHORITY_DENIED"
    history = [
        r[0]
        for r in conn.execute(
            "SELECT status FROM authority_grant_history WHERE grant_id = ?"
            " ORDER BY meta_revision",
            (child_grant_id,),
        ).fetchall()
    ]
    assert history == ["ACTIVE", "REVOKED"]
    fact = conn.execute(
        "SELECT payload_json FROM facts WHERE event_type = 'grant_revoked'"
    ).fetchone()
    assert fact is not None


def test_lazy_expiry_rejects_and_repeats_denial(store):
    conn, _realm, _tmp = store
    root_grant_id = _bootstrap(conn)
    child = run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=OTHER_ACTOR,
                permissions={"task.submit"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(expires_at_us=1),
            )
        ),
    )
    request = ReserveAuthorityUseRequest(
        grant_id=child["grant_id"],
        actor_id=OTHER_ACTOR,
        permission="task.submit",
        action_id="action://a-exp",
    )
    result = execute_command_result(conn, reserve_authority_use(request))
    assert result.error is not None
    assert result.error.code == "AUTHORITY_DENIED"
    # The denial rolled back: no use row, no history row, no fact.
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?",
            (child["grant_id"],),
        ).fetchone()[0]
        == 0
    )
    # The same denial hits every later call — expiry is evaluated lazily.
    again = execute_command_result(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child["grant_id"],
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-exp-2",
            )
        ),
    )
    assert again.error is not None
    assert again.error.code == "AUTHORITY_DENIED"
    rejected = conn.execute(
        "SELECT COUNT(*) FROM commands WHERE status = 'REJECTED'"
    ).fetchone()[0]
    assert rejected >= 2


def test_use_exhaustion_denies_and_replay_is_idempotent(store):
    conn, _realm, _tmp = store
    root_grant_id = _bootstrap(conn)
    child = run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=OTHER_ACTOR,
                permissions={"task.submit"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(max_uses=1),
            )
        ),
    )
    child_grant_id = child["grant_id"]
    ok = run_command(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-x1",
            )
        ),
    )
    assert ok["uses_count"] == 1
    denied = execute_command_result(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-x2",
            )
        ),
    )
    assert denied.error is not None
    assert denied.error.code == "AUTHORITY_DENIED"
    # Identical replay of the first use stays idempotent.
    replay = run_command(
        conn,
        reserve_authority_use(
            ReserveAuthorityUseRequest(
                grant_id=child_grant_id,
                actor_id=OTHER_ACTOR,
                permission="task.submit",
                action_id="action://a-x1",
            )
        ),
    )
    assert replay["uses_count"] == 1
    rows = conn.execute(
        "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?",
        (child_grant_id,),
    ).fetchone()[0]
    assert rows == 1


def test_delegation_consumes_parent_counter_and_detects_conflicts(store):
    conn, _realm, _tmp = store
    root_grant_id = _bootstrap(conn)
    # Parent restricted to exactly one use; the delegation spends it.
    # The parent's subject is the command actor (root), so it may delegate.
    parent = run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=ACTOR,
                permissions={"task.submit", "authority.delegate"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(
                    delegation_depth_remaining=2, max_uses=1
                ),
            )
        ),
    )
    parent_id = parent["grant_id"]
    child = run_command(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=parent_id,
                subject_id=OTHER_ACTOR,
                permissions={"task.submit"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(max_uses=1),
            )
        ),
    )
    uses_after_delegate = conn.execute(
        "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?", (parent_id,)
    ).fetchone()[0]
    assert uses_after_delegate == 1
    # Parent is now exhausted for further delegations.
    result = execute_command_result(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=parent_id,
                subject_id=OTHER_ACTOR,
                permissions={"task.submit"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
                constraints=GrantConstraints(max_uses=1),
            )
        ),
    )
    assert result.error is not None
    assert result.error.code == "RESOURCE_EXHAUSTED"
    # Unknown permission fails closed at creation (delegation containment).
    bad = execute_command_result(
        conn,
        create_grant(
            CreateGrantRequest(
                issuer_grant_id=root_grant_id,
                subject_id=OTHER_ACTOR,
                permissions={"galaxy.warp"},
                scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
            )
        ),
    )
    assert bad.error is not None
    assert bad.error.code == "AUTHORITY_DENIED"
    assert bad.error.details["dimension"] == "UNKNOWN_PERMISSION"
    # The single delegation use row for the original command stays unique.
    uses = conn.execute(
        "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?"
        " AND use_kind = 'delegate'",
        (parent_id,),
    ).fetchone()[0]
    assert uses == 1
