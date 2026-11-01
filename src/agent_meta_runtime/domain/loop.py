"""External Harness Loop contract DTOs and Host enforcement (§41.53).

The Loop itself is implemented by the external Harness, never in Runtime
product source. Runtime owns the typed DTOs, the terminal Model response
semantics and the budget/effect enforcement the Host must apply: the only
effect path is the Provider-normalized ``tool_calls`` parts in response
order — free text is never parsed for commands. One turn = one Model
Invocation plus the serial processing of all its tool calls; a model
invocation and a tool call each consume one ``step``, so ``max_steps`` is
the sum. A cancelled-before-Provider invocation still counts its
model-call (no cost) so cancellation cannot bypass the quota.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from types import MappingProxyType
from typing import Any, Mapping

from .errors import ErrorCode, StableError
from .canonical import canonical_json
from .harness import is_artifact_id
from .semantics import TaskBudget

__all__ = [
    "MAX_TOOL_CALLS_PER_RESPONSE",
    "TOOL_CALL_FINISH_REASONS",
    "TERMINAL_FINISH_REASONS",
    "ArtifactPart",
    "JsonPart",
    "ModelResponse",
    "ProviderUsage",
    "TerminalResult",
    "TextPart",
    "ToolCallPart",
    "ToolResultPart",
    "dispatchable_calls",
    "validate_response",
]

#: A single response may carry at most 16 tool_call parts (§41.53).
MAX_TOOL_CALLS_PER_RESPONSE = 16

#: finish_reason values admitted when the response carries tool_calls.
TOOL_CALL_FINISH_REASONS = frozenset({"TOOL_CALL", "STOP"})

#: finish_reason values admitted for the terminal (no tool_calls) response.
TERMINAL_FINISH_REASONS = frozenset({"STOP", "LENGTH"})


@dataclass(frozen=True, slots=True)
class TextPart:
    text: str


@dataclass(frozen=True, slots=True)
class JsonPart:
    value: Mapping[str, Any]

    def __post_init__(self) -> None:
        # Snapshot the JSON payload now. A caller mutating the original dict
        # must not change an accepted model response or persisted replay input.
        if not isinstance(self.value, (dict, MappingProxyType)):
            raise ValueError("JSON content must be an object")
        copied = json.loads(canonical_json(self.value))
        object.__setattr__(self, "value", _immutable_json(copied))


def _immutable_json(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _immutable_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_immutable_json(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class ArtifactPart:
    artifact_id: str


@dataclass(frozen=True, slots=True)
class ToolCallPart:
    call_id: str
    name: str
    arguments_json: str


@dataclass(frozen=True, slots=True)
class ToolResultPart:
    """Turn-history only; never a Task terminal result (§41.53)."""

    call_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    """``None`` means unknown — never reported as 0 (§41.53)."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_microunits: int | None = None


@dataclass(frozen=True, slots=True)
class ModelResponse:
    parts: tuple[Any, ...]
    finish_reason: str
    usage: ProviderUsage | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.parts, (list, tuple)):
            raise ValueError("model response parts must be an ordered array")
        object.__setattr__(self, "parts", tuple(self.parts))


@dataclass(frozen=True, slots=True)
class TerminalResult:
    """Full ContentPart array committed as the Task result Artifact."""

    parts: tuple[Any, ...]
    result_truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.parts, (list, tuple)):
            raise ValueError("terminal result parts must be an ordered array")
        object.__setattr__(self, "parts", tuple(self.parts))


def _part_kind(part: Any) -> str:
    if isinstance(part, TextPart):
        return "text"
    if isinstance(part, JsonPart):
        return "json"
    if isinstance(part, ArtifactPart):
        return "artifact"
    if isinstance(part, ToolCallPart):
        return "tool_call"
    if isinstance(part, ToolResultPart):
        return "tool_result"
    return "unknown"


def validate_response(response: ModelResponse) -> tuple[str, ...]:
    """Host-side response validation; returns sorted issue strings."""

    issues: list[str] = []
    if not isinstance(response, ModelResponse):
        return ("loop.response_type",)
    if not isinstance(response.parts, (tuple, list)):
        return ("loop.parts_type",)
    if not isinstance(response.finish_reason, str) or not response.finish_reason:
        issues.append("loop.finish_reason")
    tool_calls = [p for p in response.parts if isinstance(p, ToolCallPart)]
    tool_results = [p for p in response.parts if isinstance(p, ToolResultPart)]
    if len(tool_calls) > MAX_TOOL_CALLS_PER_RESPONSE:
        issues.append(f"loop.too_many_tool_calls:{len(tool_calls)}")
    call_ids = [c.call_id for c in tool_calls]
    if not all(isinstance(value, str) and value for value in call_ids):
        issues.append("loop.call_id")
    elif len(call_ids) != len(set(call_ids)):
        issues.append("loop.duplicate_call_id")
    for call in tool_calls:
        if not isinstance(call.name, str) or not call.name:
            issues.append("loop.tool_name")
        try:
            def object_without_duplicates(pairs):
                body = {}
                for key, value in pairs:
                    if key in body:
                        raise ValueError("duplicate tool argument key")
                    body[key] = value
                return body

            if not isinstance(call.arguments_json, str):
                raise ValueError("tool arguments must be JSON text")
            arguments = json.loads(call.arguments_json, object_pairs_hook=object_without_duplicates)
            if not isinstance(arguments, dict):
                raise ValueError("tool arguments must be an object")
            canonical_json(arguments)
        except (ValueError, TypeError, UnicodeError):
            issues.append("loop.tool_arguments")
    if call_ids:
        if not isinstance(response.finish_reason, str) or response.finish_reason not in TOOL_CALL_FINISH_REASONS:
            issues.append("loop.tool_call_finish_reason")
    else:
        if tool_results:
            # tool_result parts without tool_calls are illegal in a response
            issues.append("loop.stray_tool_result")
        if not isinstance(response.finish_reason, str) or response.finish_reason not in TERMINAL_FINISH_REASONS:
            issues.append("loop.terminal_finish_reason")
    kinds = [_part_kind(p) for p in response.parts]
    if "unknown" in kinds:
        issues.append("loop.unknown_part")
    for part in response.parts:
        if isinstance(part, TextPart) and not isinstance(part.text, str):
            issues.append("loop.text")
        if isinstance(part, ArtifactPart) and not is_artifact_id(part.artifact_id):
            issues.append("loop.artifact_id")
    if not tool_calls and not any(
        isinstance(part, JsonPart) or isinstance(part, ArtifactPart) and is_artifact_id(part.artifact_id)
        or isinstance(part, TextPart) and isinstance(part.text, str) and bool(part.text)
        for part in response.parts
    ):
        issues.append("loop.empty_response")
    if response.usage is not None:
        if not isinstance(response.usage, ProviderUsage):
            issues.append("loop.usage")
        elif any(value is not None and (type(value) is not int or value < 0) for value in (
            response.usage.input_tokens, response.usage.output_tokens, response.usage.cost_microunits,
        )):
            issues.append("loop.usage")
    return tuple(sorted(set(issues)))


def tool_calls_in_order(response: ModelResponse) -> list[ToolCallPart]:
    """The only effect path: Provider-normalized tool calls, response order."""

    return [p for p in response.parts if isinstance(p, ToolCallPart)]


def dispatchable_calls(response: ModelResponse) -> list[tuple[str, str]]:
    """``(call_id, capability_name)`` pairs for dispatch under the frozen surface.

    Text/JSON parts are never parsed into commands — this function is the
    single choke point the Conformance Host uses to prove free text cannot
    trigger an effect (§41.53).
    """

    return [(c.call_id, c.name) for c in tool_calls_in_order(response)]


def terminal_result(response: ModelResponse) -> TerminalResult:
    """Commit the normalized content as the Task result (§41.53).

    ``LENGTH`` marks ``result_truncated=True``; any other non-tool finish
    reason that is not STOP/LENGTH fails ``INVALID_RESULT``.
    """

    issues = validate_response(response)
    if issues:
        raise StableError(
            code=ErrorCode.INVALID_RESULT,
            message="model response violates the loop contract",
            details={"issues": list(issues)},
        )
    tool_calls = [p for p in response.parts if isinstance(p, ToolCallPart)]
    if tool_calls:
        raise StableError(
            code=ErrorCode.INVALID_RESULT,
            message="response carries tool_calls; not a terminal result",
        )
    return TerminalResult(
        parts=tuple(response.parts),
        result_truncated=response.finish_reason == "LENGTH",
    )


@dataclass(slots=True)
class TurnAccounting:
    """Per-Task budget accounting for the external Loop (§41.53)."""

    budget: TaskBudget
    turns_used: int = 0
    steps_used: int = 0
    model_calls_used: int = 0

    def begin_turn(self) -> None:
        """Reserve one model invocation: 1 turn + 1 model_call + 1 step.

        The model-call count is consumed here — cancelling before the
        Provider runs releases the cost reservation but still counts the
        call, so cancel/retry cannot bypass the quota (§41.53).
        """

        if self.turns_used + 1 > self.budget.max_turns:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="max_turns exhausted")
        if self.model_calls_used + 1 > self.budget.max_model_calls:
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED, message="max_model_calls exhausted"
            )
        if self.steps_used + 1 > self.budget.max_steps:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="max_steps exhausted")
        self.turns_used += 1
        self.model_calls_used += 1
        self.steps_used += 1

    def reserve_tool_call(self) -> None:
        """Consume one step for one tool call dispatch (response order)."""

        if self.steps_used + 1 > self.budget.max_steps:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="max_steps exhausted")
        self.steps_used += 1
