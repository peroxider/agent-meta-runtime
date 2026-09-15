"""Task/Action/Invocation state machines and records (§41.9, §41.25).

Enumerations and transition rules are defined here, centrally; the SQLite
``CHECK`` constraints in §41.34.3 are only a second line of defence. Terminal
statuses are irreversible: once a task/action/invocation is terminal no
transition may move it back to a running state, and late completions are
expressed as ``late_completion_observed`` facts, never as status changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping

from .errors import ErrorCode, StableError

__all__ = [
    "ACTION_TERMINAL_STATUSES",
    "ACTION_TRANSITIONS",
    "INVOCATION_TERMINAL_STATUSES",
    "INVOCATION_TRANSITIONS",
    "TASK_TERMINAL_STATUSES",
    "TASK_TRANSITIONS",
    "ActionRecord",
    "ActionStatus",
    "InvocationRecord",
    "InvocationStatus",
    "TaskBudget",
    "TaskRecord",
    "TaskStatus",
    "ensure_transition",
    "is_terminal",
]


class TaskStatus:
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    FAILED_RECOVERY = "FAILED_RECOVERY"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class ActionStatus:
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class InvocationStatus:
    CREATED = "CREATED"
    DISPATCHED = "DISPATCHED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


TASK_TERMINAL_STATUSES = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.FAILED_RECOVERY,
        TaskStatus.TIMED_OUT,
        TaskStatus.CANCELLED,
    }
)
ACTION_TERMINAL_STATUSES = frozenset(
    {
        ActionStatus.SUCCEEDED,
        ActionStatus.FAILED,
        ActionStatus.TIMED_OUT,
        ActionStatus.CANCELLED,
    }
)
INVOCATION_TERMINAL_STATUSES = frozenset(
    {
        InvocationStatus.SUCCEEDED,
        InvocationStatus.FAILED,
        InvocationStatus.TIMED_OUT,
        InvocationStatus.CANCELLED,
    }
)

TASK_TRANSITIONS: dict[str, frozenset[str]] = {
    TaskStatus.ACCEPTED: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.FAILED_RECOVERY,
            TaskStatus.TIMED_OUT,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.RUNNING: frozenset(TASK_TERMINAL_STATUSES),
    TaskStatus.SUCCEEDED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.FAILED_RECOVERY: frozenset(),
    TaskStatus.TIMED_OUT: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}

ACTION_TRANSITIONS: dict[str, frozenset[str]] = {
    ActionStatus.CREATED: frozenset(
        {
            ActionStatus.RUNNING,
            ActionStatus.CANCELLED,
            ActionStatus.TIMED_OUT,
        }
    ),
    ActionStatus.RUNNING: frozenset(ACTION_TERMINAL_STATUSES),
    ActionStatus.SUCCEEDED: frozenset(),
    ActionStatus.FAILED: frozenset(),
    ActionStatus.TIMED_OUT: frozenset(),
    ActionStatus.CANCELLED: frozenset(),
}

INVOCATION_TRANSITIONS: dict[str, frozenset[str]] = {
    InvocationStatus.CREATED: frozenset(
        {
            InvocationStatus.DISPATCHED,
            InvocationStatus.CANCELLED,
            InvocationStatus.TIMED_OUT,
        }
    ),
    InvocationStatus.DISPATCHED: frozenset(
        {
            InvocationStatus.RUNNING,
            InvocationStatus.FAILED,
            InvocationStatus.CANCELLED,
            InvocationStatus.TIMED_OUT,
        }
    ),
    InvocationStatus.RUNNING: frozenset(INVOCATION_TERMINAL_STATUSES),
    InvocationStatus.SUCCEEDED: frozenset(),
    InvocationStatus.FAILED: frozenset(),
    InvocationStatus.TIMED_OUT: frozenset(),
    InvocationStatus.CANCELLED: frozenset(),
}


def is_terminal(status: str, terminal_set: frozenset[str]) -> bool:
    return status in terminal_set


def ensure_transition(
    current: str,
    new: str,
    transitions: Mapping[str, frozenset[str]],
    *,
    entity: str,
    entity_id: str,
) -> str:
    """Validate one lifecycle transition; terminal states never leave."""

    allowed = transitions.get(current)
    if allowed is None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message=f"unknown {entity} status",
            details={"entity_id": entity_id, "status": current},
        )
    if new not in allowed:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message=f"illegal {entity} transition",
            details={"entity_id": entity_id, "from": current, "to": new},
        )
    return new


@dataclass(frozen=True, slots=True)
class TaskBudget:
    max_turns: int = 32
    max_steps: int = 128
    max_model_calls: int = 64
    max_effects: int = 32
    max_cost_microunits: int = 0

    def __post_init__(self) -> None:
        for name in (
            "max_turns",
            "max_steps",
            "max_model_calls",
            "max_effects",
            "max_cost_microunits",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    def extended(self, delta: Mapping[str, int]) -> "TaskBudget":
        """Effective ceiling after a positive-only adjustment (§41.25)."""

        current = {
            "max_turns": self.max_turns,
            "max_steps": self.max_steps,
            "max_model_calls": self.max_model_calls,
            "max_effects": self.max_effects,
            "max_cost_microunits": self.max_cost_microunits,
        }
        for name, amount in delta.items():
            if name not in current:
                raise ValueError(f"unknown budget field: {name}")
            if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                raise ValueError("budget adjustments must be positive integers")
            current[name] += amount
        return TaskBudget(**current)


@dataclass(frozen=True, slots=True)
class TaskRecord:
    """Durable Task aggregate; snapshot fields freeze at ACCEPTED (§41.9.2)."""

    task_id: str
    realm_id: str
    actor_id: str
    input_artifact_id: str
    serving_composition_id: str
    serving_revision: int
    capability_surface_revision: int
    capability_surface_artifact_id: str
    authority_grant_id: str | None
    budget: TaskBudget
    root_action_id: str
    status: str = TaskStatus.ACCEPTED
    accepted_at_us: int = 0
    started_at_us: int | None = None
    deadline_at_us: int | None = None
    completed_at_us: int | None = None
    result_artifact_id: str | None = None
    error: str | None = None
    state_snapshot: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in TASK_TRANSITIONS:
            raise ValueError(f"unknown task status: {self.status}")
        if self.status == TaskStatus.SUCCEEDED and self.result_artifact_id is None:
            raise ValueError("SUCCEEDED task requires result_artifact_id")
        if self.status in (TaskStatus.FAILED, TaskStatus.FAILED_RECOVERY) and (
            not self.error
        ):
            raise ValueError(f"{self.status} task requires sanitized error")
        if self.status in TASK_TERMINAL_STATUSES and self.completed_at_us is None:
            raise ValueError("terminal task requires completed_at_us")
        if (
            self.status not in TASK_TERMINAL_STATUSES
            and self.completed_at_us is not None
        ):
            raise ValueError("non-terminal task cannot have completed_at_us")

    def transition(
        self,
        new_status: str,
        *,
        now_us: int,
        result_artifact_id: str | None = None,
        error: str | None = None,
    ) -> "TaskRecord":
        ensure_transition(
            self.status,
            new_status,
            TASK_TRANSITIONS,
            entity="task",
            entity_id=self.task_id,
        )
        updates: dict = {"status": new_status}
        if new_status == TaskStatus.RUNNING:
            updates["started_at_us"] = now_us
        if new_status in TASK_TERMINAL_STATUSES:
            updates["completed_at_us"] = now_us
        if result_artifact_id is not None:
            updates["result_artifact_id"] = result_artifact_id
        if error is not None:
            updates["error"] = error
        return replace(self, **updates)


@dataclass(frozen=True, slots=True)
class ActionRecord:
    action_id: str
    actor_id: str
    intent: str
    composition_id: str
    task_id: str | None
    grant_id: str | None
    causal_parent_action_id: str | None
    status: str = ActionStatus.CREATED
    created_at_us: int = 0
    started_at_us: int | None = None
    completed_at_us: int | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in ACTION_TRANSITIONS:
            raise ValueError(f"unknown action status: {self.status}")
        if self.status in ACTION_TERMINAL_STATUSES and self.completed_at_us is None:
            raise ValueError("terminal action requires completed_at_us")

    def transition(self, new_status: str, *, now_us: int) -> "ActionRecord":
        ensure_transition(
            self.status,
            new_status,
            ACTION_TRANSITIONS,
            entity="action",
            entity_id=self.action_id,
        )
        updates: dict = {"status": new_status}
        if new_status == ActionStatus.RUNNING:
            updates["started_at_us"] = now_us
        if new_status in ACTION_TERMINAL_STATUSES:
            updates["completed_at_us"] = now_us
        return replace(self, **updates)


@dataclass(frozen=True, slots=True)
class InvocationRecord:
    invocation_id: str
    action_id: str
    kind: str
    target: str
    attempt: int
    input_artifact_id: str
    context_projection_id: str | None
    status: str = InvocationStatus.CREATED
    started_at_us: int | None = None
    completed_at_us: int | None = None
    output_artifact_id: str | None = None
    error: str | None = None
    backend_ref: str | None = None

    def __post_init__(self) -> None:
        if self.status not in INVOCATION_TRANSITIONS:
            raise ValueError(f"unknown invocation status: {self.status}")
        if self.attempt < 1:
            raise ValueError("invocation attempt starts at 1")
        if self.output_artifact_id is not None and self.error is not None:
            raise ValueError("terminal invocation has output or error, not both")
        if self.status == InvocationStatus.SUCCEEDED and (
            self.output_artifact_id is None
        ):
            raise ValueError("SUCCEEDED invocation requires output_artifact_id")
        if self.status == InvocationStatus.FAILED and not self.error:
            raise ValueError("FAILED invocation requires sanitized error")
        if self.status in INVOCATION_TERMINAL_STATUSES and self.completed_at_us is None:
            raise ValueError("terminal invocation requires completed_at_us")

    def transition(self, new_status: str, *, now_us: int) -> "InvocationRecord":
        ensure_transition(
            self.status,
            new_status,
            INVOCATION_TRANSITIONS,
            entity="invocation",
            entity_id=self.invocation_id,
        )
        updates: dict = {"status": new_status}
        if new_status == InvocationStatus.RUNNING:
            updates["started_at_us"] = now_us
        if new_status in INVOCATION_TERMINAL_STATUSES:
            updates["completed_at_us"] = now_us
        return replace(self, **updates)
