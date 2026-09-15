"""Step 07 gate: Harness installation lifecycle (§41.60)."""

from __future__ import annotations

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
    body = {"schema": "composition/v1", "realm_id": REALM, "slots": []}
    return _run(
        conn,
        activate_harness(
            ActivateHarnessRequest(
                harness_id=harness_id,
                composition_body=body,
                issuer_grant_id=ACTOR,
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
        conn,
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
    # any realm composition reference (even another harness's) blocks uninstall
    other = _install(conn, "org.example.b", "1.0.0")
    result = execute_command_result(
        conn, uninstall_harness(UninstallHarnessRequest(harness_id=other))
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.FAILED_PRECONDITION


def test_install_requires_known_harness_for_lifecycle_ops(store):
    conn, realm, _tmp = store
    result = execute_command_result(
        conn, deactivate_harness(DeactivateHarnessRequest(harness_id="harness://nope"))
    )
    assert getattr(result, "error", None) is not None
    assert result.error.code == ErrorCode.NOT_FOUND
