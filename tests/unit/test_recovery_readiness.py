"""Step 05 control-plane tests: restart recovery and readiness (§41.51,
§41.59.4)."""

from __future__ import annotations

from agent_meta_runtime.adapters.store.reconciliation import SqliteReconcilePersistence
import pytest

from agent_meta_runtime.adapters.store import (
    CompositionCreateRequest,
    SetDesiredRequest,
    create_composition,
    set_desired,
)
from agent_meta_runtime.application.outbox import OutboxDispatcher
from agent_meta_runtime.application.probes import ProbeRunner
from agent_meta_runtime.application.readiness import (
    READINESS_REASONS,
    ReadinessEvaluator,
)
from agent_meta_runtime.application.reconciler import (
    Reconciler,
    UnknownOutcomeError,
)
from agent_meta_runtime.application.recovery import RecoveryCoordinator

from conftest import ACTOR, run_command

REALM = "realm://main"
NOW_US = 1_800_000_000_000_000


def _body():
    return {
        "schema": "composition/v1",
        "realm_id": REALM,
        "slots": {
            "model": {
                "criticality": "REQUIRED",
                "degradation_policy": "REJECT_TASK",
                "capability_id": "cap-a",
                "descriptor_revision": 1,
                "health_probe": {"operation_id": "probe.model"},
            }
        },
        "wiring": [],
    }


def _ready_probes():
    return ProbeRunner(
        transport=lambda req: {"status": "READY", "reason_code": "OK"},
        sleep=lambda s: None,
        wall=lambda: 1.0,
    )


def _seed_root_grant(conn):
    from agent_meta_runtime.adapters.store.authority import RootBootstrapRequest, bootstrap_root
    run_command(conn, bootstrap_root(RootBootstrapRequest(
        realm_id=REALM, epoch_id=conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (REALM,)).fetchone()[0],
        principal_id=ACTOR, public_key=b"\x01" * 32, recovery_code_hash="a" * 64,
    )))


def _seed_desired(conn):
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(
                realm_id=REALM, body=_body(), created_by=ACTOR, revision=1
            )
        ),
    )
    run_command(
        conn,
        set_desired(SetDesiredRequest(realm_id=REALM, revision=1, expected_cas=0)),
    )


@pytest.fixture()
def rstore(store):
    conn, realm, tmp_path = store
    _seed_root_grant(conn)
    return conn, realm, tmp_path


def test_fresh_realm_is_core_ready_without_serving(rstore):
    conn, realm, tmp_path = rstore
    evaluator = ReadinessEvaluator(conn, realm_id=REALM, db_path=tmp_path / "meta.db")
    snap = evaluator.evaluate()
    # revision 0 with no harness: core_ready=true / serving_ready=false
    assert snap.core_ready is True
    assert snap.serving_ready is False
    assert snap.serving_reasons == ("NO_SERVING_COMPOSITION",)
    assert READINESS_REASONS >= set(snap.core_reasons) | set(snap.serving_reasons)


def test_unknown_cycle_blocks_core_ready(rstore):
    conn, realm, tmp_path = rstore
    _seed_desired(conn)

    def executor(step):
        raise UnknownOutcomeError("mystery")

    rc = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=REALM, slot_executor=executor, probe_runner=_ready_probes())
    assert rc.run_reconcile().status == "UNKNOWN"
    snap = ReadinessEvaluator(conn, realm_id=REALM, db_path=tmp_path / "meta.db").evaluate()
    assert snap.core_ready is False
    assert "RECONCILE_UNKNOWN" in snap.core_reasons


def test_recovered_cycle_restores_serving_readiness(rstore):
    conn, realm, tmp_path = rstore
    _seed_desired(conn)
    evaluator = ReadinessEvaluator(conn, realm_id=REALM, db_path=tmp_path / "meta.db")
    assert evaluator.evaluate().serving_ready is False

    rc = Reconciler(
        conn, persistence=SqliteReconcilePersistence(),
        realm_id=REALM,
        slot_executor=lambda step: {"instance_id": "instance://m", "state_bindings": []},
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    assert rc.run_reconcile().status == "CONVERGED"
    snap = evaluator.evaluate()
    assert snap.core_ready is True and snap.serving_ready is True


def test_recovery_redrives_unknown_after_applied_inspection(rstore):
    conn, realm, tmp_path = rstore
    _seed_desired(conn)

    def executor(step):
        raise UnknownOutcomeError("mystery")

    rcu = Reconciler(conn, persistence=SqliteReconcilePersistence(), realm_id=REALM, slot_executor=executor, probe_runner=_ready_probes())
    assert rcu.run_reconcile().status == "UNKNOWN"
    dispatcher = OutboxDispatcher(conn, handlers={})

    # UNDETERMINED → quarantined as UNKNOWN
    co = RecoveryCoordinator(
        conn, realm_id=REALM, reconciler=rcu, outbox_dispatcher=dispatcher,
        inspect_executor=lambda ctx: "UNDETERMINED", now_us=lambda: NOW_US,
    )
    report = co.recover()
    assert report.unknown_outstanding is True
    assert report.cycle_status_before == "UNKNOWN"

    # APPLIED inspection → reset to RETRYING, re-drive to convergence
    conn.execute("UPDATE composition_refs SET reconcile_status='UNKNOWN'")
    conn.commit()
    co2 = RecoveryCoordinator(
        conn, realm_id=REALM,
        reconciler=Reconciler(
            conn, persistence=SqliteReconcilePersistence(),
            realm_id=REALM,
            slot_executor=lambda step: {"instance_id": "instance://m", "state_bindings": []},
            drain_executor=lambda ctx: {"forced": False},
            probe_runner=_ready_probes(),
        ),
        outbox_dispatcher=dispatcher,
        inspect_executor=lambda ctx: "APPLIED",
        now_us=lambda: NOW_US,
    )
    report2 = co2.recover()
    assert report2.unknown_inspection == "APPLIED"
    assert report2.reconcile_outcome.status == "CONVERGED"
    assert report2.unknown_outstanding is False


def test_recovery_reconciles_resumable_cycle(rstore):
    conn, realm, tmp_path = rstore
    _seed_desired(conn)
    # simulate a crash mid-cycle (status APPLYING, external work idempotent)
    conn.execute("UPDATE composition_refs SET reconcile_status='APPLYING'")
    conn.commit()
    dispatcher = OutboxDispatcher(conn, handlers={})
    coordinator = RecoveryCoordinator(
        conn,
        realm_id=REALM,
        reconciler=Reconciler(
            conn, persistence=SqliteReconcilePersistence(),
            realm_id=REALM,
            slot_executor=lambda step: {"instance_id": "instance://m", "state_bindings": []},
            drain_executor=lambda ctx: {"forced": False},
            probe_runner=_ready_probes(),
        ),
        outbox_dispatcher=dispatcher,
        now_us=lambda: NOW_US,
    )
    report = coordinator.recover()
    assert report.cycle_status_before == "APPLYING"
    assert report.reconcile_outcome.status == "CONVERGED"


def test_orphan_quarantine_marks_operations_and_bindings(rstore):
    conn, realm, tmp_path = rstore
    _seed_desired(conn)
    conn.execute(
        "INSERT INTO operations(operation_id, realm_id, kind, command_id, status,"
        " request_json, created_at_us)"
        " VALUES ('operation://orphan', ?, 'TEST', 'task://x', 'RUNNING', x'7b7d', ?)",
        (REALM, NOW_US),
    )
    conn.execute(
        "INSERT INTO execution_bindings(backend_id, semantic_id, incarnation,"
        " request_id, payload_hash, handle_bytes, session_id, status,"
        " last_observed_at_us)"
        " VALUES ('backend://b', 'sem-1', 1, 'req-1', 'ph', x'00', 'sess',"
        " 'RUNNING', ?)",
        (NOW_US - 48 * 3600 * 1_000_000,),
    )
    conn.commit()
    dispatcher = OutboxDispatcher(conn, handlers={})
    coordinator = RecoveryCoordinator(
        conn,
        realm_id=REALM,
        reconciler=Reconciler(
            conn, persistence=SqliteReconcilePersistence(), realm_id=REALM, slot_executor=lambda step: {}, probe_runner=_ready_probes()
        ),
        outbox_dispatcher=dispatcher,
        now_us=lambda: NOW_US,
    )
    report = coordinator.recover()
    assert report.operations_quarantined == 1
    assert report.bindings_quarantined == 1
    assert (
        conn.execute(
            "SELECT status FROM operations WHERE operation_id='operation://orphan'"
        ).fetchone()[0]
        == "FAILED_RECOVERY"
    )
    assert (
        conn.execute(
            "SELECT status FROM execution_bindings WHERE request_id='req-1'"
        ).fetchone()[0]
        == "QUARANTINED"
    )
    facts = conn.execute(
        "SELECT COUNT(*) FROM facts WHERE event_type IN"
        " ('task_recovery_failed','execution_orphan_quarantined')"
    ).fetchone()[0]
    assert facts == 2


def test_critical_dead_letter_fails_core_ready(rstore):
    conn, realm, tmp_path = rstore
    conn.execute(
        "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key, payload_json,"
        " payload_hash, state, available_at_us, created_at_us)"
        " VALUES ('operation://dl', ?, 'TERMINAL_ACK', 'dk-dl', x'7b7d', 'ph',"
        " 'DEAD_LETTER', 0, ?)",
        (REALM, NOW_US),
    )
    conn.commit()
    snap = ReadinessEvaluator(conn, realm_id=REALM, db_path=tmp_path / "meta.db").evaluate()
    assert snap.core_ready is False
    assert "CRITICAL_DEAD_LETTER" in snap.core_reasons


def test_schema_mismatch_fails_core_ready(rstore):
    conn, realm, tmp_path = rstore
    conn.execute("PRAGMA user_version = 999")
    snap = ReadinessEvaluator(conn, realm_id=REALM, db_path=tmp_path / "meta.db").evaluate()
    conn.execute("PRAGMA user_version = 1")
    assert snap.core_ready is False
    assert "SCHEMA_INCOMPATIBLE" in snap.core_reasons
