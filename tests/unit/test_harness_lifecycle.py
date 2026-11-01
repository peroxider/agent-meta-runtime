"""Step 07 gate: Harness installation lifecycle (§41.60)."""

from __future__ import annotations

from agent_meta_runtime.adapters.store.reconciliation import SqliteReconcilePersistence
import pytest

from agent_meta_runtime.adapters.store import SetServingRequest, set_serving
from agent_meta_runtime.adapters.store.harness import (
    ActivateHarnessRequest,
    DeactivateHarnessRequest,
    InstallHarnessRequest,
    ScopedGrantSpec,
    UninstallHarnessRequest,
    activate_harness,
    deactivate_harness,
    install_harness,
    list_harness_rows,
    settle_harness_for_cutover,
    uninstall_harness,
)
from agent_meta_runtime.application.reconciler import Reconciler
from agent_meta_runtime.domain.authority import ScopeTarget
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from conftest import ACTOR, _seed_artifact, artifact_id, execute_command_result

REALM = "realm://main"


def _run(conn, mutator):
    result = execute_command_result(conn, mutator)
    assert not hasattr(result, "error"), result.error
    return dict(result.receipt)


def _seed_if_missing(conn, artifact: str) -> None:
    exists = conn.execute(
        "SELECT 1 FROM artifacts WHERE artifact_id = ?", (artifact,)
    ).fetchone()
    if exists is None:
        _seed_artifact(conn, artifact)


def _install(conn, name="org.example.harness", version="0.1.0") -> str:
    manifest_art = artifact_id(f"manifest:{name}:{version}")
    package_art = artifact_id(f"package:{name}:{version}")
    _seed_if_missing(conn, manifest_art)
    _seed_if_missing(conn, package_art)
    conn.commit()
    receipt = _run(
        conn,
        install_harness(
            InstallHarnessRequest(
                realm_id=REALM,
                package_name=name,
                package_version=version,
                manifest_artifact_id=manifest_art,
                package_artifact_id=package_art,
                contract_fingerprint="sha256:fp",
                installed_by=ACTOR,
            )
        ),
    )
    return receipt["harness_id"]


def _activate(conn, harness_id: str, revision: int | None = None) -> dict:
    from agent_meta_runtime.adapters.store.authority import RootBootstrapRequest, bootstrap_root
    from agent_meta_runtime.adapters.crypto import Ed25519KeyPair
    root = conn.execute("SELECT grant_id FROM authority_grants WHERE subject_id=? AND parent_grant_id IS NULL", (ACTOR,)).fetchone()
    if root is None:
        _seed_if_missing(conn, artifact_id("authority-bootstrap"))
        conn.commit()
        receipt = _run(conn, bootstrap_root(RootBootstrapRequest(
            REALM, conn.execute("SELECT epoch_id FROM realms").fetchone()[0], ACTOR,
            Ed25519KeyPair.from_private_bytes(bytes(range(32))).public_bytes_raw(), "a" * 64,
            constitution_artifact_id=artifact_id("authority-bootstrap"),
            meta_root_artifact_id=artifact_id("authority-bootstrap"),
        )))
        root = (receipt["grant_id"],)
    body = {"schema": "composition/v1", "realm_id": REALM, "slots": []}
    return _run(
        conn,
        activate_harness(
            ActivateHarnessRequest(
                harness_id=harness_id,
                composition_body=body,
                issuer_grant_id=root[0],
                scoped_grants=(
                    ScopedGrantSpec(
                        subject_id=ACTOR,
                        permissions=frozenset({"model.invoke"}),
                        scope_targets=(ScopeTarget(type="REALM_ALL"),),
                    ),
                ),
            )
        ),
    )


def _serve(conn, revision: int, composition_id: str | None = None) -> None:
    cas = int(
        conn.execute(
            "SELECT serving_cas FROM composition_refs WHERE realm_id = ?", (REALM,)
        ).fetchone()[0]
    )

    def mutator(txn):
        set_serving(
            SetServingRequest(realm_id=REALM, revision=revision, expected_cas=cas)
        )(txn)
        if composition_id is not None:
            settle_harness_for_cutover(REALM, composition_id)(txn)
        return {}

    _run(conn, mutator)


def test_install_is_idempotent_until_content_changes(store):
    conn, realm, _tmp = store
    harness_id = _install(conn)
    assert harness_id.startswith("harness://")
    # replay of the same content succeeds without a second row
    again = _install(conn)
    assert again == harness_id
    rows = list_harness_rows(conn, REALM)
    assert len(rows) == 1 and rows[0]["status"] == "INSTALLED"

    # same name/version with different bytes is an idempotency conflict
    package_art = artifact_id(f"package:other:{harness_id}")
    _seed_if_missing(conn, package_art)
    conn.commit()
    result = execute_command_result(
        conn,
        install_harness(
            InstallHarnessRequest(
                realm_id=REALM,
                package_name="org.example.harness",
                package_version="0.1.0",
                manifest_artifact_id=artifact_id("manifest:org.example.harness:0.1.0"),
                package_artifact_id=package_art,
                contract_fingerprint="sha256:fp",
                installed_by=ACTOR,
            )
        ),
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_uninstalled_package_never_revives(store):
    conn, realm, _tmp = store
    harness_id = _install(conn)
    receipt = _run(conn, uninstall_harness(UninstallHarnessRequest(harness_id=harness_id)))
    assert receipt["status"] == "UNINSTALLED"
    result = execute_command_result(conn, uninstall_harness(UninstallHarnessRequest(harness_id=harness_id)))
    assert getattr(result, "error", None) is not None  # already terminal
    # reinstall of the same name+version is refused (history never revives)
    result = execute_command_result(
        conn,
        install_harness(
            InstallHarnessRequest(
                realm_id=REALM,
                package_name="org.example.harness",
                package_version="0.1.0",
                manifest_artifact_id=artifact_id("manifest:org.example.harness:0.1.0"),
                package_artifact_id=artifact_id("package:org.example.harness:0.1.0"),
                contract_fingerprint="sha256:fp",
                installed_by=ACTOR,
            )
        ),
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.FAILED_PRECONDITION


def test_activate_creates_revision_scoped_grant_and_desired(store):
    conn, realm, _tmp = store
    harness_id = _install(conn)
    receipt = _activate(conn, harness_id)
    assert receipt["revision"] == 1
    assert len(receipt["grant_ids"]) == 1
    refs = conn.execute(
        "SELECT desired_revision, serving_revision, reconcile_status"
        " FROM composition_refs WHERE realm_id = ?",
        (REALM,),
    ).fetchone()
    assert refs[0] == 1 and refs[1] == 0
    grant = conn.execute(
        "SELECT subject_id, status, permissions_json FROM authority_grants"
        " WHERE grant_id = ?",
        (receipt["grant_ids"][0],),
    ).fetchone()
    assert grant is not None and grant[1] == "ACTIVE"
    status = conn.execute(
        "SELECT status FROM harness_installations WHERE harness_id = ?",
        (harness_id,),
    ).fetchone()[0]
    assert status == "INSTALLED"  # serving switch belongs to the Reconciler


def test_settlement_supersedes_previous_harness_and_revokes_grants(store):
    conn, realm, _tmp = store
    h1 = _install(conn, "org.example.a", "0.1.0")
    r1 = _activate(conn, h1)
    _serve(conn, r1["revision"], r1["composition_id"])
    status = conn.execute(
        "SELECT status, active_composition_id FROM harness_installations"
        " WHERE harness_id = ?",
        (h1,),
    ).fetchone()
    assert status[0] == "ACTIVE" and status[1] == r1["composition_id"]

    h2 = _install(conn, "org.example.a", "0.2.0")
    r2 = _activate(conn, h2)
    _serve(conn, r2["revision"], r2["composition_id"])

    rows = {
        r[0]: (r[1], r[2])
        for r in conn.execute(
            "SELECT harness_id, status, active_composition_id"
            " FROM harness_installations WHERE realm_id = ?",
            (REALM,),
        ).fetchall()
    }
    assert rows[h1][0] == "INACTIVE" and rows[h1][1] is None
    assert rows[h2][0] == "ACTIVE" and rows[h2][1] == r2["composition_id"]
    # h1's activation-scoped grant is revoked at supersession
    old_grant = conn.execute(
        "SELECT status FROM authority_grants WHERE grant_id = ?",
        (r1["grant_ids"][0],),
    ).fetchone()
    assert old_grant[0] == "REVOKED"
    new_grant = conn.execute(
        "SELECT status FROM authority_grants WHERE grant_id = ?",
        (r2["grant_ids"][0],),
    ).fetchone()
    assert new_grant[0] == "ACTIVE"
    # history: install, activate (still INSTALLED — serving not yet moved),
    # ACTIVE at settlement, INACTIVE at supersession
    hist = conn.execute(
        "SELECT status FROM harness_installation_history WHERE harness_id = ?"
        " ORDER BY meta_revision",
        (h1,),
    ).fetchall()
    assert [h[0] for h in hist] == ["INSTALLED", "INSTALLED", "ACTIVE", "INACTIVE"]


def test_deactivate_drains_to_revision_zero_and_settles(store):
    conn, realm, _tmp = store
    harness_id = _install(conn)
    receipt = _activate(conn, harness_id)
    _serve(conn, receipt["revision"], receipt["composition_id"])
    grants = receipt["grant_ids"]

    _run(conn, deactivate_harness(DeactivateHarnessRequest(harness_id=harness_id)))
    refs = conn.execute(
        "SELECT desired_revision, serving_revision, reconcile_status"
        " FROM composition_refs WHERE realm_id = ?",
        (REALM,),
    ).fetchone()
    assert refs[0] == 0 and refs[1] == 1  # desired cleared, serving not yet drained

    reconciler = Reconciler(
        conn, persistence=SqliteReconcilePersistence(),
        realm_id=REALM,
        slot_executor=lambda request: {},
        drain_executor=lambda request: None,
    )
    outcome = reconciler.run_reconcile()
    assert outcome.status == "DRAINED", outcome
    refs = conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " reconcile_status FROM composition_refs WHERE realm_id = ?",
        (REALM,),
    ).fetchone()
    assert refs == (0, 0, 0, "READY")
    row = conn.execute(
        "SELECT status, active_composition_id FROM harness_installations"
        " WHERE harness_id = ?",
        (harness_id,),
    ).fetchone()
    assert row[0] == "INACTIVE" and row[1] is None
    for grant_id in grants:
        status = conn.execute(
            "SELECT status FROM authority_grants WHERE grant_id = ?", (grant_id,)
        ).fetchone()[0]
        assert status == "REVOKED"

    # now uninstall succeeds (no residual references)
    result = execute_command_result(
        conn, uninstall_harness(UninstallHarnessRequest(harness_id=harness_id))
    )
    assert not hasattr(result, "error"), getattr(result, "error", None)


def test_uninstall_refuses_active_serving_harness(store):
    conn, realm, _tmp = store
    harness_id = _install(conn)
    receipt = _activate(conn, harness_id)
    _serve(conn, receipt["revision"], receipt["composition_id"])
    result = execute_command_result(
        conn, uninstall_harness(UninstallHarnessRequest(harness_id=harness_id))
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.FAILED_PRECONDITION
    # An unrelated installation is removable while another one serves.
    other = _install(conn, "org.example.b", "1.0.0")
    result = execute_command_result(
        conn, uninstall_harness(UninstallHarnessRequest(harness_id=other))
    )
    assert getattr(result, "error", None) is None
    assert result.receipt["status"] == "UNINSTALLED"


def test_install_requires_known_harness_for_lifecycle_ops(store):
    conn, realm, _tmp = store
    result = execute_command_result(
        conn, deactivate_harness(DeactivateHarnessRequest(harness_id="harness://nope"))
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.NOT_FOUND


def test_same_installation_reactivation_revokes_old_grants_and_keeps_current_generation(store):
    conn, _, _ = store
    harness_id = _install(conn)
    first = _activate(conn, harness_id)
    _serve(conn, first["revision"], first["composition_id"])
    second = _activate(conn, harness_id)
    _serve(conn, second["revision"], second["composition_id"])
    statuses = lambda receipt: [conn.execute("SELECT status FROM authority_grants WHERE grant_id=?", (gid,)).fetchone()[0] for gid in receipt["grant_ids"]]
    assert statuses(first) == ["REVOKED"]
    assert statuses(second) == ["ACTIVE"]
    assert conn.execute("SELECT status,active_composition_id FROM harness_installations WHERE harness_id=?", (harness_id,)).fetchone() == ("ACTIVE", second["composition_id"])


def test_deactivation_retires_both_serving_and_pending_activation_grants(store):
    conn, _, _ = store
    harness_id = _install(conn)
    serving = _activate(conn, harness_id)
    _serve(conn, serving["revision"], serving["composition_id"])
    pending = _activate(conn, harness_id)
    _run(conn, deactivate_harness(DeactivateHarnessRequest(harness_id)))
    outcome = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=REALM,
        slot_executor=lambda request: {}, drain_executor=lambda request: None).run_reconcile()
    assert outcome.status == "DRAINED"
    assert all(conn.execute("SELECT status FROM authority_grants WHERE grant_id=?", (gid,)).fetchone()[0] == "REVOKED"
        for gid in (*serving["grant_ids"], *pending["grant_ids"]))


@pytest.mark.parametrize("pin", ["desired", "serving", "realized", "task", "instance", "state", "capability_state", "effect_unknown"])
def test_uninstall_keeps_each_owned_reference_guard(store, pin):
    from agent_meta_runtime.domain.ids import new_uuid7
    from agent_meta_runtime.domain.canonical import canonical_json
    conn, _, _ = store
    harness_id = _install(conn)
    activation = _activate(conn, harness_id)
    composition = activation["composition_id"]
    package = conn.execute("SELECT package_artifact_id FROM harness_installations WHERE harness_id=?", (harness_id,)).fetchone()[0]
    # Runtime-owned reference fixtures test the guard, not actual execution.
    conn.execute("UPDATE composition_refs SET desired_revision=0,serving_revision=0,realized_revision=0 WHERE realm_id=?", (REALM,))
    if pin in ("desired", "serving", "realized"):
        columns = {"desired": "desired_revision", "serving": "serving_revision", "realized": "realized_revision"}
        conn.execute(f"UPDATE composition_refs SET {columns[pin]}=? WHERE realm_id=?", (activation["revision"], REALM))
    elif pin == "task":
        conn.execute("INSERT INTO capability_surfaces(realm_id,surface_revision,composition_id,artifact_id,authority_fingerprint,backend_profile_hash,created_at_us) VALUES (?,1,?,?,'fixture','fixture',1)",
            (REALM, composition, package))
        conn.execute("INSERT INTO tasks(task_id,realm_id,actor_id,input_artifact_id,serving_composition_id,serving_revision,capability_surface_revision,capability_surface_artifact_id,state_snapshot_json,budget_json,consumed_budget_json,root_action_id,status,accepted_at_us) VALUES (?,?,?,?,?,1,1,?,?,?,?,?,'ACCEPTED',1)",
            ("task://" + new_uuid7(), REALM, ACTOR, package, composition, package, canonical_json({}), canonical_json({}), canonical_json({}), "action://" + new_uuid7()))
    elif pin == "instance":
        conn.execute("INSERT INTO capabilities(capability_id,descriptor_revision,artifact_id,descriptor_json,created_at_us) VALUES ('capability://fixture',1,?,?,1)",
            (package, canonical_json({})))
        conn.execute("INSERT INTO capability_instances(instance_id,realm_id,capability_id,descriptor_revision,composition_id,placement,trust_class,status,created_at_us,updated_at_us) VALUES (?,?, 'capability://fixture',1,?,'in_process','builtin_or_signed','ACTIVE',1,1)",
            ("instance://" + new_uuid7(), REALM, composition))
    elif pin in ("state", "capability_state"):
        state, revision = "state://" + new_uuid7(), "state-revision://" + new_uuid7()
        owner = composition
        if pin == "capability_state":
            owner = "capability://fixture"
            conn.execute("INSERT INTO capabilities(capability_id,descriptor_revision,artifact_id,descriptor_json,created_at_us) VALUES (?,1,?,?,1)",
                (owner, package, canonical_json({})))
        conn.execute("INSERT INTO state_revisions(state_revision_id,state_id,owner_id,schema_id,artifact_id,created_by,created_at_us) VALUES (?,?,?,?,?,?,1)",
            (revision, state, owner, package, package, ACTOR))
        conn.execute("INSERT INTO managed_states(state_id,owner_id,schema_id,current_revision_id,cas_revision,status,updated_at_us) VALUES (?,?,?,?,1,'ACTIVE',1)",
            (state, owner, package, revision))
    else:
        action = "action://" + new_uuid7()
        conn.execute("INSERT INTO actions(action_id,actor_id,intent,composition_id,status,budget_json,consumed_budget_json,created_at_us) VALUES (?,?,'guard fixture',?,'RUNNING',?,?,1)",
            (action, ACTOR, composition, canonical_json({}), canonical_json({})))
        conn.execute("INSERT INTO effect_intents(effect_intent_id,action_id,kind,target_scope_json,idempotency_class,reversibility,required_permissions_json,required_features_json,reservation_json,request_id,status,created_at_us) VALUES (?,?,'guard-fixture',?,'NONE','IRREVERSIBLE',?,?,?,?, 'UNKNOWN',1)",
            ("effect://" + new_uuid7(), action, canonical_json({}), canonical_json([]), canonical_json([]), canonical_json({}), new_uuid7()))
    conn.commit()
    result = execute_command_result(conn, uninstall_harness(UninstallHarnessRequest(harness_id)))
    assert getattr(result, "error", None) is not None and result.error.code == ErrorCode.FAILED_PRECONDITION
    assert conn.execute("SELECT status FROM harness_installations WHERE harness_id=?", (harness_id,)).fetchone()[0] == "INSTALLED"
