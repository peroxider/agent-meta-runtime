"""Durable Task/Action/Invocation use cases as command mutators (§41.9, §41.25).

Each factory returns a ``mutator`` callable suitable for
``uow.execute_command``; the mutator receives the store transaction and
performs the canonical mutation, Fact appends and causal-edge projection in
the caller's ``BEGIN IMMEDIATE`` transaction. Terminal task statuses are
irreversible: late results are recorded as ``late_completion_observed`` Facts
and never as status changes (§41.9.2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.authority import authorize
from ...domain.canonical import canonical_json
from ...domain.fact_catalog import validate_causal_edge, validate_fact_event
from ...domain.ids import new_uuid7
from ...domain.semantics import (
    ACTION_TRANSITIONS,
    INVOCATION_TRANSITIONS,
    INVOCATION_TERMINAL_STATUSES,
    TASK_TERMINAL_STATUSES,
    ActionStatus,
    InvocationStatus,
    TaskBudget,
    TaskRecord,
    TaskStatus,
)
from ...domain.errors import ErrorCode, StableError
from ...ports.repositories import FactAppendRequest
from .surface import resolve_or_create_surface

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = [
    "InvocationCreateRequest",
    "InvocationFinishRequest",
    "TaskAcceptRequest",
    "TaskTerminalRequest",
    "accept_task",
    "advance_invocation",
    "complete_task",
    "create_invocation",
    "finish_invocation",
    "load_task",
    "mark_task_recovery_failed",
    "record_late_completion",
    "request_task_cancel",
    "start_task",
]

_TASK_TERMINAL_EVENT = {
    TaskStatus.SUCCEEDED: "task_succeeded",
    TaskStatus.FAILED: "task_failed",
    TaskStatus.FAILED_RECOVERY: "task_recovery_failed",
    TaskStatus.TIMED_OUT: "task_timed_out",
    TaskStatus.CANCELLED: "task_cancelled",
}

_ACTION_STATUS_FOR_TASK = {
    TaskStatus.SUCCEEDED: ActionStatus.SUCCEEDED,
    TaskStatus.FAILED: ActionStatus.FAILED,
    TaskStatus.FAILED_RECOVERY: ActionStatus.FAILED,
    TaskStatus.TIMED_OUT: ActionStatus.TIMED_OUT,
    TaskStatus.CANCELLED: ActionStatus.CANCELLED,
}

_TASK_COLUMNS = (
    "task_id",
    "realm_id",
    "actor_id",
    "authority_grant_id",
    "input_artifact_id",
    "serving_composition_id",
    "serving_revision",
    "capability_surface_revision",
    "capability_surface_artifact_id",
    "state_snapshot_json",
    "budget_json",
    "consumed_budget_json",
    "root_action_id",
    "status",
    "accepted_at_us",
    "started_at_us",
    "deadline_at_us",
    "completed_at_us",
    "result_artifact_id",
    "error_json",
)


@dataclass(frozen=True, slots=True)
class TaskAcceptRequest:
    task_id: str | None
    actor_id: str
    input_artifact_id: str
    serving_composition_id: str
    serving_revision: int
    budget: TaskBudget
    deadline_at_us: int | None = None
    authority_grant_id: str | None = None
    state_snapshot: Mapping[str, str] | None = None
    # None (default) resolves/reuses the Capability Surface inside the accept
    # transaction via the §41.59.1 cache key (§41.59.1).
    capability_surface_revision: int | None = None
    capability_surface_artifact_id: str | None = None
    backend_profile_hash: str = "portable-v1"
    reserve_grant_use: bool = False
    prepared_surface: Mapping[str, Any] | None = None
    prepared_view: Mapping[str, Any] | None = None
    context_profile_artifact_id: str | None = None
    causal_parent_action_id: str | None = None


@dataclass(frozen=True, slots=True)
class TaskTerminalRequest:
    status: str
    result_artifact_id: str | None = None
    error: str | None = None
    reason_code: str = "completed"


@dataclass(frozen=True, slots=True)
class InvocationCreateRequest:
    invocation_id: str | None
    action_id: str
    kind: str
    target: str
    input_artifact_id: str
    attempt: int = 1
    context_projection_id: str | None = None


@dataclass(frozen=True, slots=True)
class InvocationFinishRequest:
    invocation_id: str
    output_artifact_id: str | None = None
    error: str | None = None
    status: str | None = None
    reason_code: str = "completed"
    latency_us: int | None = None


def _fact(
    txn: "_SqliteStoreTransaction",
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    actor_id: str,
    action_id: str | None = None,
) -> str:
    validate_fact_event(entity_type, event_type, 1, dict(payload))
    return txn.append_fact(
        FactAppendRequest(
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            schema_version=1,
            payload=dict(payload),
            occurred_at_us=txn.recorded_at_us,
            actor_id=actor_id,
            action_id=action_id,
        )
    )


def _append_edge(
    txn: "_SqliteStoreTransaction",
    *,
    fact_id: str,
    edge_type: str,
    from_id: str,
    to_id: str,
) -> None:
    validate_causal_edge(edge_type, from_id, to_id)
    txn.execute(
        "INSERT OR IGNORE INTO causal_edges(realm_id, from_id, edge_type, to_id,"
        " source_fact_id) VALUES (?, ?, ?, ?, ?)",
        (txn._envelope.realm_id, from_id, edge_type, to_id, fact_id),
    )


def _check_grant_at_accept(
    txn: "_SqliteStoreTransaction",
    *,
    grant_id: str,
    actor_id: str,
    action_key: str,
    reserve: bool,
) -> None:
    """Re-authorize ``task.submit`` against the current grant state at accept.

    The check runs in the accept transaction: a revoked, expired or exhausted
    grant denies the acceptance immediately (§41.59.1).
    """

    from .authority import _load_grant, _reserve_use_row

    grant = _load_grant(
        txn, grant_id, now_us=txn.recorded_at_us, actor_id=actor_id
    )
    uses_count = txn._conn.execute(
        "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ? AND NOT(action_id=? AND use_kind='command')",
        (grant_id, txn._envelope.command_id),
    ).fetchone()[0]
    reason = authorize(
        grant,
        subject_id=actor_id,
        permission="task.submit",
        resource_realm=txn._envelope.realm_id,
        resource_target=None,
        epoch_id=txn._conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (txn._envelope.realm_id,)).fetchone()[0],
        now_us=txn.recorded_at_us,
        uses_count=uses_count,
    )
    if reason is not None:
        _fact(
            txn,
            entity_type="authority",
            entity_id=grant_id,
            event_type="authority_denied",
            payload={
                "reason_code": reason,
                "permission": "task.submit",
                "action_id": action_key,
            },
            actor_id=actor_id,
        )
        raise StableError(
            code=ErrorCode.AUTHORITY_DENIED,
            message="task acceptance denied by authority check",
            details={"grant_id": grant_id, "reason": reason},
        )
    if reserve:
        _reserve_use_row(txn, grant_id, action_key, "accept", {})


def _require_task_row(
    txn: "_SqliteStoreTransaction", task_id: str
) -> tuple:
    cols = ", ".join(_TASK_COLUMNS)
    row = txn._conn.execute(
        f"SELECT {cols} FROM tasks WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="task not found",
            details={"task_id": task_id},
        )
    return row


def _task_record_from_row(row: tuple) -> TaskRecord:
    (
        task_id,
        realm_id,
        actor_id,
        authority_grant_id,
        input_artifact_id,
        serving_composition_id,
        serving_revision,
        capability_surface_revision,
        capability_surface_artifact_id,
        state_snapshot_json,
        budget_json,
        _consumed_budget_json,
        root_action_id,
        status,
        accepted_at_us,
        started_at_us,
        deadline_at_us,
        completed_at_us,
        result_artifact_id,
        error_json,
    ) = row
    return TaskRecord(
        task_id=task_id,
        realm_id=realm_id,
        actor_id=actor_id,
        input_artifact_id=input_artifact_id,
        serving_composition_id=serving_composition_id,
        serving_revision=serving_revision,
        capability_surface_revision=capability_surface_revision,
        capability_surface_artifact_id=capability_surface_artifact_id,
        authority_grant_id=authority_grant_id,
        budget=TaskBudget(**json.loads(budget_json)),
        root_action_id=root_action_id,
        status=status,
        accepted_at_us=accepted_at_us,
        started_at_us=started_at_us,
        deadline_at_us=deadline_at_us,
        completed_at_us=completed_at_us,
        result_artifact_id=result_artifact_id,
        error=json.loads(error_json) if error_json is not None else None,
        state_snapshot=json.loads(state_snapshot_json),
    )


def _persist_task(txn: "_SqliteStoreTransaction", record: TaskRecord) -> None:
    txn.execute(
        "UPDATE tasks SET status = ?, started_at_us = ?, completed_at_us = ?,"
        " result_artifact_id = ?, error_json = ? WHERE task_id = ?",
        (
            record.status,
            record.started_at_us,
            record.completed_at_us,
            record.result_artifact_id,
            canonical_json_text(record.error),
            record.task_id,
        ),
    )


def canonical_json_text(value: str | None) -> bytes | None:
    return None if value is None else canonical_json(value)


# ------------------------------------------------------------ task use cases --
def accept_task(request: TaskAcceptRequest):
    """Accept a task: ACCEPTED row + root Action (CREATED) in one transaction."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        task_id = request.task_id or f"task://{new_uuid7()}"
        root_action_id = f"action://{new_uuid7()}"
        snapshot = dict(request.state_snapshot or {})
        if request.capability_surface_revision is None:
            surface = resolve_or_create_surface(
                txn,
                composition_id=request.serving_composition_id,
                actor_id=request.actor_id,
                backend_profile_hash=request.backend_profile_hash,
                prepared=request.prepared_surface,
            )
            surface_revision = surface["surface_revision"]
            surface_artifact_id = surface["surface_artifact_id"]
        else:
            surface_revision = request.capability_surface_revision
            surface_artifact_id = request.capability_surface_artifact_id
        if request.prepared_view is not None:
            from .task_snapshot import acceptance_view, register_staged_artifact
            view = acceptance_view(txn._conn, realm_id=txn._envelope.realm_id,
                actor_id=request.actor_id, composition_id=request.serving_composition_id,
                serving_revision=request.serving_revision, surface_artifact_id=surface_artifact_id,
                authority_fingerprint=request.prepared_surface["authority_fingerprint"],
                backend_profile_hash=request.backend_profile_hash, context_profile_artifact_id=request.context_profile_artifact_id,
                causal_parent_action_id=request.causal_parent_action_id, now_us=txn.recorded_at_us)
            if view["content"] != request.prepared_view["content"]:
                raise StableError(code=ErrorCode.REVISION_CONFLICT, message="Task acceptance View changed before admission")
            snapshot = view["value"]["state_snapshot"]
            register_staged_artifact(txn, request.prepared_view, kind="task_view")
        if request.authority_grant_id:
            _check_grant_at_accept(
                txn,
                grant_id=request.authority_grant_id,
                actor_id=request.actor_id,
                action_key=task_id,
                reserve=request.reserve_grant_use,
            )
        budget_json = json.dumps(
            {
                "max_turns": request.budget.max_turns,
                "max_steps": request.budget.max_steps,
                "max_model_calls": request.budget.max_model_calls,
                "max_effects": request.budget.max_effects,
                "max_cost_microunits": request.budget.max_cost_microunits,
            }
        ).encode("utf-8")
        empty_json = b"{}"
        try:
            txn.execute(
                "INSERT INTO tasks(task_id, realm_id, actor_id, authority_grant_id,"
                " input_artifact_id, serving_composition_id, serving_revision,"
                " capability_surface_revision, capability_surface_artifact_id,"
                " state_snapshot_json, budget_json, consumed_budget_json,"
                " root_action_id, status, accepted_at_us, deadline_at_us)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACCEPTED', ?, ?)",
                (
                    task_id,
                    txn._envelope.realm_id,
                    request.actor_id,
                    request.authority_grant_id,
                    request.input_artifact_id,
                    request.serving_composition_id,
                    request.serving_revision,
                    surface_revision,
                    surface_artifact_id,
                    json.dumps(snapshot).encode("utf-8"),
                    budget_json,
                    empty_json,
                    root_action_id,
                    txn.recorded_at_us,
                    request.deadline_at_us,
                ),
            )
            txn.execute(
                "INSERT INTO actions(action_id, task_id, actor_id, intent,"
                " composition_id, grant_id, causal_parent_action_id, status, budget_json,"
                " consumed_budget_json, created_at_us)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'CREATED', ?, ?, ?)",
                (
                    root_action_id,
                    task_id,
                    request.actor_id,
                    "task_root",
                    request.serving_composition_id,
                    request.authority_grant_id,
                    request.causal_parent_action_id,
                    budget_json,
                    empty_json,
                    txn.recorded_at_us,
                ),
            )
        except Exception as exc:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message=f"task accept failed: {exc}",
                details={"task_id": task_id},
            ) from exc
        fact_id = _fact(
            txn,
            entity_type="task",
            entity_id=task_id,
            event_type="task_accepted",
            payload={
                "input_artifact_id": request.input_artifact_id,
                "serving_composition_id": request.serving_composition_id,
                "serving_revision": request.serving_revision,
                **({"acceptance_view_artifact_id": request.prepared_view["artifact_id"]}
                   if request.prepared_view is not None else {}),
            },
            actor_id=request.actor_id,
        )
        _append_edge(
            txn,
            fact_id=fact_id,
            edge_type="part_of",
            from_id=root_action_id,
            to_id=task_id,
        )
        if request.causal_parent_action_id is not None:
            _append_edge(txn, fact_id=fact_id, edge_type="caused_by", from_id=root_action_id, to_id=request.causal_parent_action_id)
        if request.authority_grant_id:
            _append_edge(
                txn,
                fact_id=fact_id,
                edge_type="authorized_by",
                from_id=root_action_id,
                to_id=request.authority_grant_id,
            )
        return {"task_id": task_id, "root_action_id": root_action_id}

    return mutator


def start_task(task_id: str, *, reason_code: str = "started"):
    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        record = _task_record_from_row(_require_task_row(txn, task_id))
        updated = record.transition(TaskStatus.RUNNING, now_us=txn.recorded_at_us)
        _persist_task(txn, updated)
        txn.execute(
            "UPDATE actions SET status = ?, started_at_us = ? WHERE action_id = ?",
            (ActionStatus.RUNNING, txn.recorded_at_us, record.root_action_id),
        )
        _fact(
            txn,
            entity_type="task",
            entity_id=task_id,
            event_type="task_started",
            payload={
                "reason_code": reason_code,
                "old_status": record.status,
                "new_status": TaskStatus.RUNNING,
            },
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        _fact(
            txn,
            entity_type="action",
            entity_id=record.root_action_id,
            event_type="action_started",
            payload={
                "reason_code": reason_code,
                "old_status": ActionStatus.CREATED,
                "new_status": ActionStatus.RUNNING,
            },
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        return {"task_id": task_id, "status": TaskStatus.RUNNING}

    return mutator


def complete_task(task_id: str, terminal: TaskTerminalRequest):
    """Commit a terminal task status, its Fact and root-action close together."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        record = _task_record_from_row(_require_task_row(txn, task_id))
        event_type = _TASK_TERMINAL_EVENT.get(terminal.status)
        if event_type is None:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="unknown terminal task status",
                details={"status": terminal.status},
            )
        action_row = txn._conn.execute(
            "SELECT status FROM actions WHERE action_id = ?",
            (record.root_action_id,),
        ).fetchone()
        action_old = action_row[0] if action_row else ActionStatus.CREATED
        action_status = _ACTION_STATUS_FOR_TASK[terminal.status]
        try:
            updated = record.transition(
                terminal.status,
                now_us=txn.recorded_at_us,
                result_artifact_id=terminal.result_artifact_id,
                error=terminal.error,
            )
        except ValueError as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=str(exc),
                details={"task_id": task_id, "status": terminal.status},
            ) from exc
        _persist_task(txn, updated)
        txn.execute(
            "UPDATE actions SET status = ?, completed_at_us = ?, error_json = ?"
            " WHERE action_id = ?",
            (
                action_status,
                txn.recorded_at_us,
                canonical_json_text(terminal.error),
                record.root_action_id,
            ),
        )
        _fact(
            txn,
            entity_type="task",
            entity_id=task_id,
            event_type=event_type,
            payload={
                "reason_code": terminal.reason_code,
                "old_status": record.status,
                "new_status": terminal.status,
            },
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        _fact(
            txn,
            entity_type="action",
            entity_id=record.root_action_id,
            event_type="action_finished",
            payload={
                "reason_code": terminal.reason_code,
                "old_status": action_old,
                "new_status": action_status,
            },
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        return {
            "task_id": task_id,
            "status": terminal.status,
            "completed_at_us": updated.completed_at_us,
        }

    return mutator


def request_task_cancel(task_id: str, *, reason_code: str = "requested"):
    """Cancel is a request, not a result: only a Fact is appended (§41.25)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        record = _task_record_from_row(_require_task_row(txn, task_id))
        if record.status in TASK_TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="task already terminal; cancel request refused",
                details={"task_id": task_id, "status": record.status},
            )
        _fact(
            txn,
            entity_type="task",
            entity_id=task_id,
            event_type="task_cancel_requested",
            payload={"reason_code": reason_code},
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        return {"task_id": task_id, "cancel_requested": True}

    return mutator


def mark_task_recovery_failed(task_id: str, *, error: str, reason_code: str = "recovery_failed"):
    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        return complete_task(
            task_id,
            TaskTerminalRequest(
                status=TaskStatus.FAILED_RECOVERY, error=error, reason_code=reason_code
            ),
        )(txn)

    return mutator


def record_late_completion(task_id: str, *, result_artifact_id: str | None = None, error: str | None = None):
    """Late result on a terminal task: Fact only, status never changes."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        record = _task_record_from_row(_require_task_row(txn, task_id))
        if record.status not in TASK_TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="late completion requires a terminal task",
                details={"task_id": task_id, "status": record.status},
            )
        payload: dict[str, Any] = {
            "reason_code": "late_result",
            "task_status": record.status,
        }
        if result_artifact_id is not None:
            payload["result_artifact_id"] = result_artifact_id
        if error is not None:
            payload["error"] = error
        _fact(
            txn,
            entity_type="action",
            entity_id=record.root_action_id,
            event_type="late_completion_observed",
            payload=payload,
            actor_id=record.actor_id,
            action_id=record.root_action_id,
        )
        return {"task_id": task_id, "late_completion_recorded": True}

    return mutator


# ------------------------------------------------------- invocation use cases --
def advance_invocation(invocation_id: str, new_status: str, *, reason_code: str = "advanced"):
    """Move a non-terminal invocation along CREATED→DISPATCHED→RUNNING.

    Terminal commit goes through :func:`finish_invocation`, which owns the
    output/error exclusive rule.
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        row = txn._conn.execute(
            "SELECT i.status, i.action_id, a.actor_id FROM invocations i"
            " JOIN actions a ON i.action_id = a.action_id"
            " WHERE i.invocation_id = ?",
            (invocation_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="invocation not found",
                details={"invocation_id": invocation_id},
            )
        old_status, action_id, actor_id = row
        if old_status in INVOCATION_TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="invocation already terminal",
                details={"invocation_id": invocation_id, "status": old_status},
            )
        if new_status not in INVOCATION_TRANSITIONS[old_status]:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="illegal invocation transition",
                details={"invocation_id": invocation_id, "from": old_status, "to": new_status},
            )
        if new_status in INVOCATION_TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="terminal invocation commit requires finish_invocation",
                details={"invocation_id": invocation_id, "to": new_status},
            )
        if new_status == InvocationStatus.RUNNING:
            txn.execute(
                "UPDATE invocations SET status = ?, started_at_us = ?"
                " WHERE invocation_id = ?",
                (new_status, txn.recorded_at_us, invocation_id),
            )
        else:
            txn.execute(
                "UPDATE invocations SET status = ? WHERE invocation_id = ?",
                (new_status, invocation_id),
            )
        _fact(
            txn,
            entity_type="invocation",
            entity_id=invocation_id,
            event_type="invocation_attempted",
            payload={
                "old_status": old_status,
                "new_status": new_status,
                "reason_code": reason_code,
            },
            actor_id=actor_id,
            action_id=action_id,
        )
        return {"invocation_id": invocation_id, "status": new_status}

    return mutator


def create_invocation(request: InvocationCreateRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        invocation_id = request.invocation_id or f"invocation://{new_uuid7()}"
        action_row = txn._conn.execute(
            "SELECT task_id, actor_id FROM actions WHERE action_id = ?",
            (request.action_id,),
        ).fetchone()
        if action_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="action not found",
                details={"action_id": request.action_id},
            )
        task_id, actor_id = action_row
        txn.execute(
            "INSERT INTO invocations(invocation_id, action_id, kind, target, attempt,"
            " input_artifact_id, context_projection_id, status, usage_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'CREATED', ?)",
            (
                invocation_id,
                request.action_id,
                request.kind,
                request.target,
                request.attempt,
                request.input_artifact_id,
                request.context_projection_id,
                b"{}",
            ),
        )
        fact_id = _fact(
            txn,
            entity_type="invocation",
            entity_id=invocation_id,
            event_type="invocation_created",
            payload={
                "action_id": request.action_id,
                "kind": request.kind,
                "target": request.target,
                "attempt": request.attempt,
            },
            actor_id=actor_id,
            action_id=request.action_id,
        )
        _append_edge(
            txn,
            fact_id=fact_id,
            edge_type="part_of",
            from_id=invocation_id,
            to_id=request.action_id,
        )
        if task_id:
            _append_edge(
                txn,
                fact_id=fact_id,
                edge_type="part_of",
                from_id=request.action_id,
                to_id=task_id,
            )
        return {"invocation_id": invocation_id}

    return mutator


def finish_invocation(request: InvocationFinishRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict:
        row = txn._conn.execute(
            "SELECT i.status, i.action_id, a.actor_id FROM invocations i"
            " JOIN actions a ON i.action_id = a.action_id"
            " WHERE i.invocation_id = ?",
            (request.invocation_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="invocation not found",
                details={"invocation_id": request.invocation_id},
            )
        old_status, action_id, actor_id = row
        if old_status in INVOCATION_TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="invocation already terminal",
                details={"invocation_id": request.invocation_id, "status": old_status},
            )
        if request.output_artifact_id is not None and request.error is not None:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="terminal invocation has output or error, not both",
            )
        if request.output_artifact_id is not None:
            new_status = request.status or InvocationStatus.SUCCEEDED
        elif request.error is not None:
            new_status = request.status or InvocationStatus.FAILED
        else:
            new_status = request.status or InvocationStatus.FAILED
        if new_status not in INVOCATION_TRANSITIONS[old_status]:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="illegal invocation transition",
                details={"from": old_status, "to": new_status},
            )
        error_json = canonical_json_text(request.error)
        txn.execute(
            "UPDATE invocations SET status = ?, completed_at_us = ?,"
            " output_artifact_id = ?, error_json = ?, latency_us = ?"
            " WHERE invocation_id = ?",
            (
                new_status,
                txn.recorded_at_us,
                request.output_artifact_id,
                error_json,
                request.latency_us,
                request.invocation_id,
            ),
        )
        payload: dict[str, Any] = {
            "reason_code": request.reason_code,
            "old_status": old_status,
            "new_status": new_status,
        }
        fact_id = _fact(
            txn,
            entity_type="invocation",
            entity_id=request.invocation_id,
            event_type="invocation_finished",
            payload=payload,
            actor_id=actor_id,
            action_id=action_id,
        )
        if request.output_artifact_id:
            _append_edge(
                txn,
                fact_id=fact_id,
                edge_type="produced",
                from_id=request.invocation_id,
                to_id=request.output_artifact_id,
            )
        return {"invocation_id": request.invocation_id, "status": new_status}

    return mutator


# --------------------------------------------------------------------- reads --
def load_task(conn, task_id: str) -> TaskRecord | None:
    """Read-side loader outside any command transaction."""

    cols = ", ".join(_TASK_COLUMNS)
    row = conn.execute(f"SELECT {cols} FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    return None if row is None else _task_record_from_row(row)
