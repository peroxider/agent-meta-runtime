"""Pure validation of the existing task.submit/v1 scalar contract."""

from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .semantics import TaskBudget


def parse_task_submission(payload):
    if not isinstance(payload, dict) or set(payload) - {"input_artifact_id", "budget", "deadline_at_us"} or not is_artifact_id(payload.get("input_artifact_id")):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid Task submission fields or input ArtifactId")
    budget = payload.get("budget", {})
    if not isinstance(budget, dict):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Task budget must be an object")
    try:
        budget = TaskBudget(**budget)
    except (TypeError, ValueError) as exc:
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Task budget requires known nonnegative integer fields") from exc
    deadline = payload.get("deadline_at_us")
    if deadline is not None and (type(deadline) is not int or deadline < 0):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Task deadline must be nonnegative integer microseconds")
    return payload["input_artifact_id"], budget, deadline
