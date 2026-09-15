"""Step 02 gate: Task/Action/Invocation durable semantics (§41.9, §41.25)."""

from __future__ import annotations

from agent_meta_runtime.adapters.store import (
    InvocationCreateRequest,
    InvocationFinishRequest,
    TaskAcceptRequest,
    TaskTerminalRequest,
    accept_task,
    advance_invocation,
    complete_task,
    create_invocation,
    finish_invocation,
    load_task,
    mark_task_recovery_failed,
    record_late_completion,
    request_task_cancel,
    start_task,
)
from agent_meta_runtime.domain.semantics import InvocationStatus, TaskBudget, TaskStatus
from conftest import ACTOR, artifact_id, execute_command_result, run_command

OUTPUT = artifact_id("output")


def _accept(conn, realm, composition, input_artifact, surface_artifact, **kw):
    return run_command(
        conn,
        accept_task(
            TaskAcceptRequest(
                task_id=kw.get("task_id"),
                actor_id=ACTOR,
                input_artifact_id=input_artifact,
                serving_composition_id=composition,
                serving_revision=1,
                capability_surface_revision=1,
                capability_surface_artifact_id=surface_artifact,
                budget=kw.get("budget", TaskBudget()),
                deadline_at_us=kw.get("deadline_at_us"),
                authority_grant_id=kw.get("authority_grant_id"),
                state_snapshot=kw.get("state_snapshot"),
            )
        ),
    )


def test_accept_creates_task_and_root_action(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    record = load_task(conn, receipt["task_id"])
    assert record.status == TaskStatus.ACCEPTED
    assert record.root_action_id == receipt["root_action_id"]
    assert record.serving_composition_id == composition
    row = conn.execute(
        "SELECT status, task_id FROM actions WHERE action_id = ?",
        (receipt["root_action_id"],),
    ).fetchone()
    assert row == ("CREATED", receipt["task_id"])
    edge = conn.execute(
        "SELECT 1 FROM causal_edges WHERE realm_id = ? AND from_id = ?"
        " AND edge_type = 'part_of' AND to_id = ?",
        (realm, receipt["root_action_id"], receipt["task_id"]),
    ).fetchone()
    assert edge is not None


def test_lifecycle_transitions_and_frozen_fields(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(
        conn,
        realm,
        composition,
        input_artifact,
        surface_artifact,
        state_snapshot={"state://s1": "state-revision://r1"},
    )
    task_id = receipt["task_id"]
    run_command(conn, start_task(task_id))
    running = load_task(conn, task_id)
    assert running.status == TaskStatus.RUNNING
    assert running.started_at_us is not None
    assert running.state_snapshot == {"state://s1": "state-revision://r1"}
    run_command(
        conn,
        complete_task(
            task_id,
            TaskTerminalRequest(status=TaskStatus.SUCCEEDED, result_artifact_id=OUTPUT),
        ),
    )
    done = load_task(conn, task_id)
    assert done.status == TaskStatus.SUCCEEDED
    assert done.completed_at_us is not None
    assert done.result_artifact_id == OUTPUT


def test_terminal_status_is_irreversible(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    task_id = receipt["task_id"]
    run_command(conn, start_task(task_id))
    run_command(
        conn,
        complete_task(
            task_id,
            TaskTerminalRequest(status=TaskStatus.SUCCEEDED, result_artifact_id=OUTPUT),
        ),
    )
    rejected = execute_command_result(
        conn,
        complete_task(
            task_id, TaskTerminalRequest(status=TaskStatus.FAILED, error="late fail")
        ),
    )
    assert hasattr(rejected, "error")
    assert rejected.error.code == "INVALID_ARGUMENT"
    assert load_task(conn, task_id).status == TaskStatus.SUCCEEDED


def test_cancel_request_is_fact_not_status(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    task_id = receipt["task_id"]
    run_command(conn, start_task(task_id))
    run_command(conn, request_task_cancel(task_id, reason_code="operator"))
    assert load_task(conn, task_id).status == TaskStatus.RUNNING
    fact = conn.execute(
        "SELECT 1 FROM facts WHERE event_type = 'task_cancel_requested'"
        " AND entity_id = ?",
        (task_id,),
    ).fetchone()
    assert fact is not None
    after_terminal = execute_command_result(
        conn,
        complete_task(
            task_id, TaskTerminalRequest(status=TaskStatus.CANCELLED)
        ),
    )
    assert not hasattr(after_terminal, "error")
    refused = execute_command_result(conn, request_task_cancel(task_id))
    assert hasattr(refused, "error")
    assert refused.error.code == "FAILED_PRECONDITION"


def test_late_completion_recorded_as_fact_only(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    task_id = receipt["task_id"]
    run_command(conn, start_task(task_id))
    run_command(
        conn,
        complete_task(
            task_id, TaskTerminalRequest(status=TaskStatus.SUCCEEDED, result_artifact_id=OUTPUT)
        ),
    )
    run_command(
        conn,
        record_late_completion(task_id, result_artifact_id=input_artifact),
    )
    assert load_task(conn, task_id).status == TaskStatus.SUCCEEDED
    fact = conn.execute(
        "SELECT payload_json FROM facts WHERE event_type ="
        " 'late_completion_observed'"
    ).fetchone()
    assert fact is not None
    # A non-terminal task must refuse late completion.
    receipt2 = _accept(conn, realm, composition, input_artifact, surface_artifact)
    refused = execute_command_result(
        conn, record_late_completion(receipt2["task_id"])
    )
    assert hasattr(refused, "error")
    assert refused.error.code == "FAILED_PRECONDITION"


def test_recovery_failed_from_accepted(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    task_id = receipt["task_id"]
    run_command(
        conn, mark_task_recovery_failed(task_id, error="bootstrap crashed")
    )
    record = load_task(conn, task_id)
    assert record.status == TaskStatus.FAILED_RECOVERY
    assert record.error == "bootstrap crashed"
    assert record.completed_at_us is not None


def test_invocation_lifecycle_and_produced_edge(semantic_env):
    conn, realm, composition, input_artifact, surface_artifact = semantic_env
    receipt = _accept(conn, realm, composition, input_artifact, surface_artifact)
    root_action = receipt["root_action_id"]
    output = OUTPUT
    inv_receipt = run_command(
        conn,
        create_invocation(
            InvocationCreateRequest(
                invocation_id=None,
                action_id=root_action,
                kind="model",
                target="model://primary",
                input_artifact_id=input_artifact,
            )
        ),
    )
    invocation_id = inv_receipt["invocation_id"]
    run_command(conn, advance_invocation(invocation_id, InvocationStatus.DISPATCHED))
    run_command(conn, advance_invocation(invocation_id, InvocationStatus.RUNNING))
    run_command(
        conn,
        finish_invocation(
            InvocationFinishRequest(
                invocation_id=invocation_id, output_artifact_id=output
            )
        ),
    )
    status, out = conn.execute(
        "SELECT status, output_artifact_id FROM invocations WHERE invocation_id = ?",
        (invocation_id,),
    ).fetchone()
    assert (status, out) == ("SUCCEEDED", output)
    edge = conn.execute(
        "SELECT 1 FROM causal_edges WHERE realm_id = ? AND from_id = ?"
        " AND edge_type = 'produced' AND to_id = ?",
        (realm, invocation_id, output),
    ).fetchone()
    assert edge is not None
    again = execute_command_result(
        conn,
        finish_invocation(
            InvocationFinishRequest(invocation_id=invocation_id, error="dup")
        ),
    )
    assert hasattr(again, "error")
    assert again.error.code == "FAILED_PRECONDITION"
