"""Private journal tests through actual SQLite command/Facts transactions."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from agent_meta_runtime.adapters.store import (
    InvocationCreateRequest,
    TaskAcceptRequest,
    TaskTerminalRequest,
    accept_task,
    advance_invocation,
    complete_task,
    connect_store,
    create_invocation,
    request_task_cancel,
    start_task,
)
from agent_meta_runtime.adapters.store import scratch_journal as journal
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.semantics import InvocationStatus, TaskBudget, TaskStatus
from conftest import ACTOR, artifact_id, execute_command_result, run_command
from test_semantic_tasks import _accept


def _invocation(conn, action):
    value = run_command(
        conn,
        create_invocation(
            InvocationCreateRequest(
                None,
                action,
                "tool",
                "capability://seed.scratch#execute",
                artifact_id("input"),
            )
        ),
    )["invocation_id"]
    run_command(conn, advance_invocation(value, InvocationStatus.DISPATCHED))
    run_command(conn, advance_invocation(value, InvocationStatus.RUNNING))
    return value


@pytest.fixture()
def live(semantic_env):
    conn, realm, composition, source, surface = semantic_env
    task = _accept(
        conn,
        realm,
        composition,
        source,
        surface,
        deadline_at_us=time.time_ns() // 1000 + 3_600_000_000,
    )
    run_command(conn, start_task(task["task_id"]))
    invocation = _invocation(conn, task["root_action_id"])
    workspace = "workspace://" + new_uuid7()

    def create_workspace(txn):
        txn.execute(
            "INSERT INTO workspaces VALUES (?,?,?,?,?,'ACTIVE',?,NULL,NULL)",
            (
                workspace,
                realm,
                task["root_action_id"],
                "scratch/" + new_uuid7(),
                1024 * 1024,
                txn.recorded_at_us,
            ),
        )
        return {}

    run_command(conn, create_workspace)
    request = journal.reserve_session(
        invocation, workspace_id=workspace, backend_request_id=invocation
    )
    session = run_command(conn, request)["session_id"]
    run_command(conn, journal.activate_session(session))
    return conn, task, invocation, workspace, session, request


def _reserve(conn, session, invocation, **kwargs):
    return run_command(
        conn,
        journal.reserve_cell(
            session,
            invocation,
            source_artifact_id=kwargs.get("source", artifact_id("input")),
            timeout_us=kwargs.get("timeout", 1_000_000),
        ),
    )


def _error(conn, mutate, code):
    result = execute_command_result(conn, mutate)
    assert result.error.code == code
    return result


def _facts(conn, session, event=None):
    rows = conn.execute(
        "SELECT event_type,payload_json FROM facts WHERE entity_type='scratch' AND entity_id=? ORDER BY seq",
        (session,),
    ).fetchall()
    return [
        (name, json.loads(raw)) for name, raw in rows if event is None or name == event
    ]


def test_root_origin_and_session_reservation_replay(live):
    conn, task, invocation, workspace, session, request = live
    before = _facts(conn, session)
    assert run_command(conn, request) == {"session_id": session, "status": "ACTIVE"}
    assert _facts(conn, session) == before
    origin = before[0][1]
    assert origin["invocation_id"] == invocation
    assert origin["owner_principal_id"] == ACTOR
    assert origin["workspace_id"] == workspace
    row = conn.execute(
        "SELECT actor_id,action_id FROM facts WHERE entity_id=? ORDER BY seq LIMIT 1",
        (session,),
    ).fetchone()
    assert row == (ACTOR, task["root_action_id"])
    _error(
        conn,
        journal.reserve_session(
            invocation,
            workspace_id=workspace,
            backend_request_id=invocation,
            idle_ttl_us=1,
        ),
        ErrorCode.IDEMPOTENCY_CONFLICT,
    )


def test_second_realm_lifetime_and_backend_rebinding_are_denied(live):
    conn, task, invocation, workspace, session, request = live
    _error(
        conn,
        journal.reserve_session(
            invocation,
            workspace_id=workspace,
            backend_request_id="invocation://" + new_uuid7(),
        ),
        ErrorCode.IDEMPOTENCY_CONFLICT,
    )
    second = _invocation(conn, task["root_action_id"])
    _error(
        conn,
        journal.reserve_session(
            second, workspace_id=workspace, backend_request_id=second
        ),
        ErrorCode.ALREADY_RUNNING,
    )
    assert conn.execute("SELECT COUNT(*) FROM scratch_sessions").fetchone()[0] == 1


def test_cell_order_sources_output_edges_and_exact_replay(live):
    conn, task, invocation, workspace, session, request = live
    one = _reserve(conn, session, invocation)
    assert one["ordinal"] == 1 and one["status"] == "RESERVED"
    run_command(conn, journal.record_cell_dispatch(session, invocation))
    result = run_command(
        conn,
        journal.observe_cell(
            session,
            invocation,
            outcome="SUCCEEDED",
            receipt_artifact_id=artifact_id("output"),
        ),
    )
    count = len(_facts(conn, session))
    assert _reserve(conn, session, invocation) == result
    assert (
        run_command(
            conn,
            journal.observe_cell(
                session,
                invocation,
                outcome="SUCCEEDED",
                receipt_artifact_id=artifact_id("output"),
            ),
        )
        == result
    )
    assert len(_facts(conn, session)) == count
    second = _invocation(conn, task["root_action_id"])
    assert _reserve(conn, session, second)["ordinal"] == 2
    edges = conn.execute(
        "SELECT edge_type,to_id FROM causal_edges WHERE from_id=?",
        (task["root_action_id"],),
    ).fetchall()
    assert ("used", artifact_id("input")) in edges
    assert ("produced", artifact_id("output")) in edges


@pytest.mark.parametrize("change", ["source", "timeout"])
def test_changed_cell_request_is_not_a_replay(live, change):
    conn, _, invocation, _, session, _ = live
    _reserve(conn, session, invocation)
    kwargs = (
        {"source_artifact_id": artifact_id("output"), "timeout_us": 1_000_000}
        if change == "source"
        else {"source_artifact_id": artifact_id("input"), "timeout_us": 2_000_000}
    )
    _error(
        conn,
        journal.reserve_cell(session, invocation, **kwargs),
        ErrorCode.IDEMPOTENCY_CONFLICT,
    )


def test_dispatch_is_not_repeatable_and_result_requires_dispatch(live):
    conn, _, invocation, _, session, _ = live
    _reserve(conn, session, invocation)
    _error(
        conn,
        journal.observe_cell(
            session,
            invocation,
            outcome="SUCCEEDED",
            receipt_artifact_id=artifact_id("output"),
        ),
        ErrorCode.FAILED_PRECONDITION,
    )
    run_command(conn, journal.record_cell_dispatch(session, invocation))
    _error(
        conn,
        journal.record_cell_dispatch(session, invocation),
        ErrorCode.FAILED_PRECONDITION,
    )


@pytest.mark.parametrize(
    "dispatched,expected", [(False, "NOT_DISPATCHED"), (True, "UNKNOWN")]
)
def test_owner_loss_recovery_never_reexecutes_or_reopens(live, dispatched, expected):
    conn, task, invocation, workspace, session, _ = live
    _reserve(conn, session, invocation)
    if dispatched:
        run_command(conn, journal.record_cell_dispatch(session, invocation))
    run_command(conn, journal.lose_session(session))
    recovered = _reserve(conn, session, invocation)
    assert recovered["status"] == expected
    assert recovered["receipt_artifact_id"] is None
    count = len(_facts(conn, session))
    run_command(conn, journal.lose_session(session))
    assert len(_facts(conn, session)) == count
    _error(
        conn,
        journal.record_cell_dispatch(session, invocation),
        ErrorCode.HANDLE_EXPIRED,
    )
    second = _invocation(conn, task["root_action_id"])
    _error(
        conn,
        journal.reserve_cell(
            session, second, source_artifact_id=artifact_id("input"), timeout_us=1
        ),
        ErrorCode.HANDLE_EXPIRED,
    )
    _error(
        conn,
        journal.observe_cell(
            session,
            invocation,
            outcome="SUCCEEDED",
            receipt_artifact_id=artifact_id("output"),
        ),
        ErrorCode.IDEMPOTENCY_CONFLICT,
    )


def test_native_outcome_is_retained_after_task_terminal_and_epoch_change(live):
    conn, task, invocation, _, session, _ = live
    _reserve(conn, session, invocation)
    run_command(conn, journal.record_cell_dispatch(session, invocation))
    run_command(
        conn,
        complete_task(
            task["task_id"],
            TaskTerminalRequest(status=TaskStatus.FAILED, error="normalization failed"),
        ),
    )

    def rotate(txn):
        txn.execute(
            "UPDATE realms SET epoch_id=? WHERE realm_id=?",
            ("epoch://" + new_uuid7(), "realm://main"),
        )
        return {}

    run_command(conn, rotate)
    result = run_command(
        conn,
        journal.observe_cell(
            session,
            invocation,
            outcome="SUCCEEDED",
            receipt_artifact_id=artifact_id("output"),
        ),
    )
    assert result["status"] == "SUCCEEDED"
    run_command(conn, journal.lose_session(session))
    assert (
        _facts(conn, session, "scratch_cell_observed")[-1][1]["status"] == "SUCCEEDED"
    )


@pytest.mark.parametrize("phase", ["reserve", "dispatch", "observe", "lose"])
def test_command_failure_rolls_back_projection_facts_edges_and_revision(live, phase):
    conn, _, invocation, _, session, _ = live
    if phase != "reserve":
        _reserve(conn, session, invocation)
    if phase in ("observe", "lose"):
        run_command(conn, journal.record_cell_dispatch(session, invocation))
    before = (
        conn.execute("SELECT * FROM scratch_sessions").fetchall(),
        conn.execute("SELECT * FROM realms").fetchall(),
        conn.execute("SELECT * FROM facts").fetchall(),
        conn.execute("SELECT * FROM causal_edges").fetchall(),
    )
    operation = {
        "reserve": journal.reserve_cell(
            session, invocation, source_artifact_id=artifact_id("input"), timeout_us=1
        ),
        "dispatch": journal.record_cell_dispatch(session, invocation),
        "observe": journal.observe_cell(session, invocation, outcome="UNKNOWN"),
        "lose": journal.lose_session(session),
    }[phase]

    def fail_after(txn):
        operation(txn)
        raise StableError(code=ErrorCode.INTERNAL, message="injected after mutation")

    _error(conn, fail_after, ErrorCode.INTERNAL)
    after = (
        conn.execute("SELECT * FROM scratch_sessions").fetchall(),
        conn.execute("SELECT * FROM realms").fetchall(),
        conn.execute("SELECT * FROM facts").fetchall(),
        conn.execute("SELECT * FROM causal_edges").fetchall(),
    )
    assert after == before


def test_two_real_writer_connections_serialize_cell_admission(live):
    conn, task, first, _, session, _ = live
    second = _invocation(conn, task["root_action_id"])
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    barrier = Barrier(2)

    def reserve(invocation):
        other = connect_store(path)
        try:
            barrier.wait(timeout=5)
            result = execute_command_result(
                other,
                journal.reserve_cell(
                    session,
                    invocation,
                    source_artifact_id=artifact_id("input"),
                    timeout_us=1,
                ),
            )
            return (
                result.error.code
                if hasattr(result, "error")
                else result.receipt["ordinal"]
            )
        finally:
            other.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(reserve, value) for value in (first, second)]
        assert sorted((f.result() for f in futures), key=str) == [
            1,
            ErrorCode.ALREADY_RUNNING,
        ]
    assert len(_facts(conn, session, "scratch_cell_reserved")) == 1


def test_restart_reads_actual_committed_pending_cell(live):
    conn, _, invocation, _, session, _ = live
    _reserve(conn, session, invocation)
    run_command(conn, journal.record_cell_dispatch(session, invocation))
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    other = connect_store(path)
    try:
        run_command(other, journal.lose_session(session))
        assert _reserve(other, session, invocation)["status"] == "UNKNOWN"
    finally:
        other.close()
    assert conn.execute(
        "SELECT status FROM scratch_sessions WHERE session_id=?", (session,)
    ).fetchone() == ("LOST",)


def test_release_requires_pending_recovery_and_workspace_confirmation(live):
    conn, _, invocation, workspace, session, _ = live
    _reserve(conn, session, invocation)
    run_command(conn, journal.record_cell_dispatch(session, invocation))
    assert (
        run_command(conn, journal.begin_release(session))["workspace_id"] == workspace
    )
    _error(conn, journal.confirm_release(session), ErrorCode.FAILED_PRECONDITION)
    run_command(conn, journal.lose_session(session))
    run_command(conn, journal.begin_release(session))
    _error(conn, journal.confirm_release(session), ErrorCode.FAILED_PRECONDITION)

    def cleaned(txn):
        txn.execute(
            "UPDATE workspaces SET status='RELEASED',released_at_us=? WHERE workspace_id=?",
            (txn.recorded_at_us, workspace),
        )
        return {}

    run_command(conn, cleaned)
    assert run_command(conn, journal.confirm_release(session))["status"] == "RELEASED"
    count = len(_facts(conn, session))
    assert run_command(conn, journal.begin_release(session))["status"] == "RELEASED"
    assert run_command(conn, journal.confirm_release(session))["status"] == "RELEASED"
    assert len(_facts(conn, session)) == count
    _error(conn, journal.activate_session(session), ErrorCode.HANDLE_EXPIRED)


def test_binding_handles_expire_with_lost_owner(live):
    conn, task, _, _, session, _ = live

    def binding(txn):
        txn.execute(
            "INSERT INTO scratch_bindings VALUES (?,?,1,?,?,?,?,?,'LIVE',?)",
            (
                session,
                "answer",
                "builtins",
                "int",
                artifact_id("input"),
                task["root_action_id"],
                "opaque-hash",
                b"{}",
            ),
        )
        return {}

    run_command(conn, binding)
    run_command(conn, journal.lose_session(session))
    assert conn.execute(
        "SELECT status FROM scratch_bindings WHERE session_id=?", (session,)
    ).fetchone() == ("EXPIRED",)


def test_source_integrity_and_cell_lifetime_bound(live, monkeypatch):
    conn, _, invocation, _, session, _ = live
    _error(
        conn,
        journal.reserve_cell(
            session, invocation, source_artifact_id=artifact_id("missing"), timeout_us=1
        ),
        ErrorCode.INTEGRITY_ERROR,
    )
    monkeypatch.setattr(journal, "MAX_CELLS", 0)
    _error(
        conn,
        journal.reserve_cell(
            session, invocation, source_artifact_id=artifact_id("input"), timeout_us=1
        ),
        ErrorCode.RESOURCE_EXHAUSTED,
    )


def test_projection_tamper_and_legacy_session_are_not_adopted(live):
    conn, _, invocation, _, session, _ = live

    def tamper(txn):
        txn.execute(
            "UPDATE scratch_sessions SET workspace_id=? WHERE session_id=?",
            ("workspace://" + new_uuid7(), session),
        )
        return {}

    run_command(conn, tamper)
    _error(conn, journal.activate_session(session), ErrorCode.INTEGRITY_ERROR)
    _error(
        conn,
        journal.reserve_cell(
            "scratch://legacy",
            invocation,
            source_artifact_id=artifact_id("input"),
            timeout_us=1,
        ),
        ErrorCode.INVALID_ARGUMENT,
    )


@pytest.mark.parametrize(
    "scope", ["owner", "epoch", "composition", "cancel", "task_deadline", "idle"]
)
def test_dispatch_rechecks_root_scope_and_current_liveness(live, scope):
    conn, task, invocation, _, session, _ = live
    _reserve(conn, session, invocation, timeout=30_000_000)
    checked_invocation = invocation
    if scope == "owner":
        composition, surface = conn.execute(
            "SELECT serving_composition_id,capability_surface_artifact_id FROM tasks WHERE task_id=?",
            (task["task_id"],),
        ).fetchone()
        other_task = run_command(
            conn,
            accept_task(
                TaskAcceptRequest(
                    task_id=None,
                    actor_id="principal://agent/" + new_uuid7(),
                    input_artifact_id=artifact_id("input"),
                    serving_composition_id=composition,
                    serving_revision=1,
                    capability_surface_revision=1,
                    capability_surface_artifact_id=surface,
                    budget=TaskBudget(),
                )
            ),
        )
        run_command(conn, start_task(other_task["task_id"]))
        checked_invocation = _invocation(conn, other_task["root_action_id"])
    elif scope == "composition":
        # Build a malformed child as corruption input. Frozen production
        # identity triggers remain enabled; no Task or Action is rewritten.
        action = "action://" + new_uuid7()

        def wrong_child(txn):
            txn.execute(
                "INSERT INTO actions(action_id,task_id,actor_id,intent,composition_id,status,budget_json,consumed_budget_json,created_at_us) "
                "SELECT ?,task_id,actor_id,intent,?,'RUNNING',budget_json,consumed_budget_json,created_at_us FROM actions WHERE action_id=?",
                (action, "composition://" + new_uuid7(), task["root_action_id"]),
            )
            return {}

        run_command(conn, wrong_child)
        checked_invocation = _invocation(conn, action)

    def change(txn):
        if scope == "epoch":
            txn.execute(
                "UPDATE realms SET epoch_id=? WHERE realm_id=?",
                ("epoch://" + new_uuid7(), "realm://main"),
            )
        elif scope == "cancel":
            request_task_cancel(task["task_id"])(txn)
        elif scope == "idle":
            txn.execute(
                "UPDATE scratch_sessions SET idle_expires_at_us=0 WHERE session_id=?",
                (session,),
            )
        return {}

    run_command(conn, change)
    expected = {
        "owner": ErrorCode.AUTHORITY_DENIED,
        "epoch": ErrorCode.AUTHORITY_DENIED,
        "composition": ErrorCode.INTEGRITY_ERROR,
        "cancel": ErrorCode.FAILED_PRECONDITION,
        "task_deadline": ErrorCode.DEADLINE_EXCEEDED,
        "idle": ErrorCode.HANDLE_EXPIRED,
    }[scope]

    def dispatch(txn):
        if scope == "task_deadline":
            txn.recorded_at_us = conn.execute(
                "SELECT deadline_at_us FROM tasks WHERE task_id=?", (task["task_id"],)
            ).fetchone()[0]
        return journal.record_cell_dispatch(session, checked_invocation)(txn)

    _error(conn, dispatch, expected)
    assert not _facts(conn, session, "scratch_cell_dispatched")


def test_expired_cell_admission_is_not_a_native_unknown_effect(live):
    conn, _, invocation, _, session, _ = live
    _reserve(conn, session, invocation, timeout=1)
    _error(
        conn,
        journal.record_cell_dispatch(session, invocation),
        ErrorCode.DEADLINE_EXCEEDED,
    )
    run_command(conn, journal.lose_session(session))
    assert _reserve(conn, session, invocation, timeout=1)["status"] == "NOT_DISPATCHED"


def test_actual_owned_kernel_executes_without_root_writer_transaction(live, tmp_path):
    pytest.importorskip("ipykernel")
    import asyncio
    from agent_meta_runtime.adapters.cas import FilesystemCas
    from agent_meta_runtime.adapters.scratch_worker import ScratchWorker
    from agent_meta_runtime.adapters.store.task_snapshot import register_staged_artifact
    from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
    from test_store_uow import _mutator

    conn, _, invocation, _, session, _ = live
    cas = FilesystemCas(tmp_path / "cas")
    # A test-owned orchestration, not a public admission implementation.
    source = "import time\nfrom pathlib import Path\nPath('entered').write_text('ready')\ntime.sleep(1)\nprint(6*7)"

    def stage(content):
        return {
            "content": content,
            "artifact_id": "artifact://sha256/" + sha256_hex(content),
            "manifest": {
                "storage_relpath": cas.put(content),
                "size_bytes": len(content),
            },
        }

    staged_source = stage(source.encode("utf-8"))

    def reserve(txn):
        txn.execute(
            "INSERT INTO artifacts VALUES (?, 'test_source', 'text/x-python', ?, 1, ?, ?, ?, ?, 'VALID')",
            (
                staged_source["artifact_id"],
                len(staged_source["content"]),
                ACTOR,
                txn.recorded_at_us,
                b"[]",
                canonical_json(staged_source["manifest"]),
            ),
        )
        return journal.reserve_cell(
            session,
            invocation,
            source_artifact_id=staged_source["artifact_id"],
            timeout_us=30_000_000,
        )(txn)

    reserved = run_command(conn, reserve)

    async def run():
        worker = await ScratchWorker(
            workspace_root=tmp_path, workspace=tmp_path / "kernel"
        ).start()
        try:
            run_command(conn, journal.record_cell_dispatch(session, invocation))
            executing = asyncio.create_task(worker.execute(source))
            try:
                async with asyncio.timeout(10):
                    while not (worker.workspace / "entered").exists():
                        await asyncio.sleep(0.01)
                assert not executing.done()
                assert not conn.in_transaction
                # A second real connection commits a Root Fact while the
                # independent kernel remains in its cell. No mocked writer.
                other = connect_store(
                    conn.execute("PRAGMA database_list").fetchone()[2]
                )
                try:
                    run_command(
                        other,
                        _mutator({"kernel_cell_in_flight": True}, with_outbox=False),
                    )
                finally:
                    other.close()
                result = await executing
            finally:
                if not executing.done():
                    executing.cancel()
                    await asyncio.gather(executing, return_exceptions=True)
            assert result.ordinal == reserved["ordinal"] == 1
            assert result.stdout.strip() == "42" and result.error_type is None
            receipt = stage(
                canonical_json({"stdout": result.stdout, "ordinal": result.ordinal})
            )

            def observed(txn):
                register_staged_artifact(txn, receipt, kind="test_scratch_receipt")
                return journal.observe_cell(
                    session,
                    invocation,
                    outcome="SUCCEEDED",
                    receipt_artifact_id=receipt["artifact_id"],
                )(txn)

            assert run_command(conn, observed)["status"] == "SUCCEEDED"
            assert (
                _facts(conn, session, "scratch_cell_reserved")[0][1][
                    "source_artifact_id"
                ]
                == staged_source["artifact_id"]
            )
        finally:
            await worker.close()

    asyncio.run(run())


@pytest.mark.parametrize("value", [True, 0, -1, 30_000_001, 1.5, "1"])
def test_timeout_bounds_are_strict(value):
    with pytest.raises(StableError) as error:
        journal.reserve_cell(
            "scratch-session://" + new_uuid7(),
            "invocation://" + new_uuid7(),
            source_artifact_id=artifact_id("input"),
            timeout_us=value,
        )
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
