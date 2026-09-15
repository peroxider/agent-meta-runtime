"""Step 05 control-plane tests: Reconciler A–H round (§41.38, §41.59.2/3).

Covers the plan's crash-point/fault-injection deliverables and the
refs/state/history atomic cutover requirement.
"""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import (
    CompositionCreateRequest,
    SetDesiredRequest,
    StateCreateRequest,
    StateRevisionRegistration,
    StateWriteRequest,
    create_composition,
    create_state,
    register_migration_target,
    set_desired,
    write_state_revision,
)
from agent_meta_runtime.application.probes import ProbeRunner
from agent_meta_runtime.application.reconciler import (
    Reconciler,
    UnknownOutcomeError,
    topological_slots,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError

from conftest import ACTOR, artifact_id, run_command

REALM = "realm://main"


def _body(tag="ok"):
    return {
        "schema": "composition/v1",
        "realm_id": REALM,
        "tag": tag,
        "slots": {
            "model": {
                "criticality": "REQUIRED",
                "degradation_policy": "REJECT_TASK",
                "capability_id": "cap-a",
                "descriptor_revision": 1,
                "health_probe": {"operation_id": "probe.model"},
            },
            "cache": {
                "criticality": "OPTIONAL",
                "degradation_policy": "OMIT",
                "capability_id": "cap-b",
                "descriptor_revision": 1,
                "health_probe": {"operation_id": "probe.cache"},
            },
        },
        "wiring": [
            {
                "consumer_slot": "cache",
                "provider_slot": "model",
                "requirement_interface": "i1",
            }
        ],
    }


def _ready_probes():
    return ProbeRunner(
        transport=lambda req: {"status": "READY", "reason_code": "OK"},
        sleep=lambda s: None,
        wall=lambda: 1.0,
    )


def _degraded_cache_probes():
    return ProbeRunner(
        transport=lambda req: (
            {"status": "DEGRADED", "reason_code": "SLOW"}
            if req["slot"] == "cache"
            else {"status": "READY", "reason_code": "OK"}
        ),
        sleep=lambda s: None,
        wall=lambda: 1.0,
    )


def _ok_executor(step):
    return {"instance_id": f"instance://{step['slot']}", "state_bindings": []}


def _refs(conn):
    return conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " reconcile_status FROM composition_refs WHERE realm_id = ?",
        (REALM,),
    ).fetchone()


def _seed_desired(conn, *, revision=1):
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(
                realm_id=REALM,
                body=_body(f"v{revision}"),
                created_by=ACTOR,
                revision=revision,
            )
        ),
    )
    run_command(
        conn,
        set_desired(
            SetDesiredRequest(realm_id=REALM, revision=revision, expected_cas=revision - 1)
        ),
    )


def _seed_artifacts(conn, tags):
    for tag in tags:
        conn.execute(
            "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
            " schema_version, created_by, created_at_us, parents_json, manifest_json,"
            " integrity_status) VALUES (?, 'code', 'application/json', 0, 1, ?, 1, ?, ?, 'VALID')",
            (artifact_id(tag), ACTOR, b"{}", b"{}"),
        )
    conn.commit()


def test_wiring_dag_orders_provider_before_consumer():
    steps = topological_slots(_body())
    assert [s["slot"] for s in steps] == ["model", "cache"]
    with pytest.raises(StableError) as exc:
        topological_slots(
            {
                "schema": "composition/v1",
                "slots": {
                    "a": {"criticality": "REQUIRED", "degradation_policy": "REJECT_TASK"},
                    "b": {"criticality": "REQUIRED", "degradation_policy": "REJECT_TASK"},
                },
                "wiring": [
                    {"consumer_slot": "a", "provider_slot": "b"},
                    {"consumer_slot": "b", "provider_slot": "a"},
                ],
            }
        )
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT


def test_full_round_converges_refs_and_records_slot_facts(store):
    conn, realm, _tmp = store
    _seed_desired(conn)
    calls: list[str] = []

    def executor(step):
        calls.append(step["request_id"])
        return _ok_executor(step)

    rc = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_degraded_cache_probes(),
    )
    outcome = rc.run_reconcile()
    assert outcome.status == "CONVERGED"
    assert outcome.realized_revision == 1
    assert _refs(conn) == (1, 1, 1, "READY")
    assert outcome.slots[0].status == "READY"
    assert outcome.slots[1].status == "DEGRADED" and outcome.slots[1].passed
    # slot facts committed in short transactions (E)
    degraded = conn.execute(
        "SELECT COUNT(*) FROM facts WHERE event_type='instance_degraded'"
        " AND entity_id='instance://cache'"
    ).fetchone()[0]
    assert degraded == 1
    # outbox item for the semantic transition exists exactly once
    assert (
        conn.execute("SELECT COUNT(*) FROM outbox WHERE kind='RECONCILE_REQUEST'").fetchone()[0]
        == 1
    )
    # ref history has rows for every ref movement
    assert conn.execute("SELECT COUNT(*) FROM composition_ref_history").fetchone()[0] >= 3


def test_failed_required_slot_preserves_old_serving(store):
    conn, realm, _tmp = store
    _seed_desired(conn)

    def executor(step):
        if step["slot"] == "model":
            raise RuntimeError("backend down")
        return _ok_executor(step)

    rc = Reconciler(
        conn, realm_id=REALM, slot_executor=executor, probe_runner=_ready_probes()
    )
    outcome = rc.run_reconcile()
    assert outcome.status == "FAILED" and outcome.reason_code == "SLOT_EXECUTOR_ERROR"
    assert _refs(conn)[1] == 0  # serving not moved: nothing was serving
    assert _refs(conn)[3] == "FAILED"
    # rerunning from FAILED is fail-closed: the cycle must be reset deliberately
    with pytest.raises(StableError) as exc:
        rc.run_reconcile()
    assert exc.value.code == ErrorCode.FAILED_PRECONDITION


def test_unknown_outcome_marks_cycle_and_fact(store):
    conn, realm, _tmp = store
    _seed_desired(conn)

    def executor(step):
        raise UnknownOutcomeError("may or may not have committed")

    rc = Reconciler(conn, realm_id=REALM, slot_executor=executor, probe_runner=_ready_probes())
    outcome = rc.run_reconcile()
    assert outcome.status == "UNKNOWN"
    assert outcome.reason_code == "EXTERNAL_EFFECT_UNKNOWN"
    assert _refs(conn)[3] == "UNKNOWN"
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM facts WHERE event_type='external_effect_unknown'"
        ).fetchone()[0]
        == 1
    )


def test_drain_failure_degrades_then_resume_converges(store):
    conn, realm, _tmp = store
    _seed_desired(conn)
    rc_fail = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=_ok_executor,
        drain_executor=lambda ctx: (_ for _ in ()).throw(RuntimeError("drain stuck")),
        probe_runner=_ready_probes(),
    )
    outcome = rc_fail.run_reconcile()
    assert outcome.status == "DEGRADED" and outcome.reason_code == "DRAIN_FAILED"
    assert _refs(conn) == (1, 1, 0, "DEGRADED")  # serving switched, realized held

    rc_ok = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=_ok_executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    resumed = rc_ok.run_reconcile()
    assert resumed.status == "CONVERGED"
    assert _refs(conn) == (1, 1, 1, "READY")


def test_converged_cycle_is_idempotent(store):
    conn, realm, _tmp = store
    _seed_desired(conn)
    calls: list[str] = []

    def executor(step):
        calls.append(step["request_id"])
        return _ok_executor(step)

    rc = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    rc.run_reconcile()
    before = len(calls)
    again = rc.run_reconcile()
    assert again.status == "ALREADY_CONVERGED"
    assert len(calls) == before  # no external re-execution
    assert len(set(calls)) == len(calls)  # one stable request id per slot


def test_state_binding_cutover_binds_state_and_serving_in_one_terminal_txn(store):
    conn, realm, _tmp = store
    _seed_desired(conn)
    _seed_artifacts(conn, ("a", "b", "c"))
    created = run_command(
        conn,
        create_state(
            StateCreateRequest(owner_id=ACTOR, schema_id="s/v1", artifact_id=artifact_id("a"))
        ),
    )
    written = run_command(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=created["state_id"],
                expected_revision_id=created["state_revision_id"],
                expected_cas_revision=created["cas_revision"],
                schema_id="s/v1",
                artifact_id=artifact_id("b"),
                writer_id=ACTOR,
            )
        ),
    )
    source_rev = written["state_revision_id"]
    registered: dict[str, str] = {}

    def executor(step):
        if step["slot"] != "model":
            return _ok_executor(step)  # only model carries the state binding
        reg = {
            "state_id": created["state_id"],
            "source_revision_id": source_rev,
            "schema_id": "s/v2",
            "artifact_id": artifact_id("c"),
        }
        res = run_command(
            conn, register_migration_target(StateRevisionRegistration(**reg))
        )
        registered["target"] = res["state_revision_id"]
        return {
            "instance_id": "instance://model",
            "state_bindings": [dict(reg, state_revision_id=res["state_revision_id"])],
        }

    rc = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    outcome = rc.run_reconcile()
    assert outcome.status == "CONVERGED"
    assert (
        conn.execute(
            "SELECT current_revision_id FROM managed_states WHERE state_id=?",
            (created["state_id"],),
        ).fetchone()[0]
        == registered["target"]
    )
    assert _refs(conn) == (1, 1, 1, "READY")
    # state ref history recorded the binding movements
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM state_ref_history WHERE state_id=?",
            (created["state_id"],),
        ).fetchone()[0]
        >= 2
    )


def test_stale_state_source_rolls_back_whole_cutover(store):
    conn, realm, _tmp = store
    _seed_desired(conn)
    _seed_artifacts(conn, ("a", "b", "c", "d"))
    created = run_command(
        conn,
        create_state(
            StateCreateRequest(owner_id=ACTOR, schema_id="s/v1", artifact_id=artifact_id("a"))
        ),
    )
    written = run_command(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=created["state_id"],
                expected_revision_id=created["state_revision_id"],
                expected_cas_revision=created["cas_revision"],
                schema_id="s/v1",
                artifact_id=artifact_id("b"),
                writer_id=ACTOR,
            )
        ),
    )
    old_source = written["state_revision_id"]

    def first_executor(step):
        if step["slot"] != "model":
            return _ok_executor(step)  # only model carries the state binding
        reg = {
            "state_id": created["state_id"],
            "source_revision_id": old_source,
            "schema_id": "s/v2",
            "artifact_id": artifact_id("c"),
        }
        res = run_command(
            conn, register_migration_target(StateRevisionRegistration(**reg))
        )
        return {
            "instance_id": "instance://model",
            "state_bindings": [dict(reg, state_revision_id=res["state_revision_id"])],
        }

    rc = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=first_executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    assert rc.run_reconcile().status == "CONVERGED"
    current = conn.execute(
        "SELECT current_revision_id, cas_revision FROM managed_states WHERE state_id=?",
        (created["state_id"],),
    ).fetchone()
    advanced = run_command(
        conn,
        write_state_revision(
            StateWriteRequest(
                state_id=created["state_id"],
                expected_revision_id=current[0],
                expected_cas_revision=current[1],
                schema_id="s/v2",
                artifact_id=artifact_id("b"),
                writer_id=ACTOR,
            )
        ),
    )
    fresh_target = run_command(
        conn,
        register_migration_target(
            StateRevisionRegistration(
                state_id=created["state_id"],
                source_revision_id=advanced["state_revision_id"],
                schema_id="s/v3",
                artifact_id=artifact_id("d"),
            )
        ),
    )["state_revision_id"]

    conn.execute(
        "UPDATE composition_refs SET desired_revision=0, serving_revision=0,"
        " realized_revision=0, desired_cas=2, serving_cas=2, realized_cas=2,"
        " reconcile_status='PENDING'"
    )
    conn.commit()
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(
                realm_id=REALM, body=_body("v3"), created_by=ACTOR, revision=2
            )
        ),
    )
    run_command(
        conn, set_desired(SetDesiredRequest(realm_id=REALM, revision=2, expected_cas=2))
    )

    def stale_executor(step):
        return {
            "instance_id": "instance://model",
            "state_bindings": [
                {
                    "state_id": created["state_id"],
                    "source_revision_id": old_source,  # stale: current is advanced
                    "schema_id": "s/v3",
                    "artifact_id": artifact_id("d"),
                    "state_revision_id": fresh_target,
                }
            ],
        }

    rc2 = Reconciler(
        conn,
        realm_id=REALM,
        slot_executor=stale_executor,
        drain_executor=lambda ctx: {"forced": False},
        probe_runner=_ready_probes(),
    )
    outcome = rc2.run_reconcile()
    assert outcome.status == "SUPERSEDED"
    assert outcome.reason_code == "SERVING_CAS_CONFLICT"
    assert _refs(conn)[1] == 0  # old serving preserved
    assert (
        conn.execute(
            "SELECT current_revision_id FROM managed_states WHERE state_id=?",
            (created["state_id"],),
        ).fetchone()[0]
        == advanced["state_revision_id"]
    )  # target stayed unbound
