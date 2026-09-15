"""Test-only Conformance Harness (§41.57.3, §41.53).

Minimal deterministic Provider, single-step Loop and echo Capability used
exclusively by Runtime contract/E2E tests. IDs are namespaced to
``capability://conformance.*``; the build MUST exclude this package and
these IDs from wheel/sdist/SBOM (asserted by
``tests/unit/test_conformance_harness.py``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.loop import (
    ModelResponse,
    TaskBudget,
    TurnAccounting,
    terminal_result,
    tool_calls_in_order,
    validate_response,
)

__all__ = [
    "CAPABILITY_ECHO",
    "ConformanceLoop",
    "DeterministicProvider",
    "echo_execute",
]

CAPABILITY_ECHO = "capability://conformance.echo"


class DeterministicProvider:
    """Scripted terminal responses; identical input replays identically."""

    def __init__(self, scripted: Sequence[ModelResponse]) -> None:
        self._scripted = list(scripted)

    def invoke(self, request: Mapping[str, Any]) -> ModelResponse:
        if not self._scripted:
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message="conformance provider script exhausted",
            )
        return self._scripted.pop(0)


def echo_execute(arguments: Mapping[str, Any]) -> dict[str, Any]:
    return {"echoed": dict(arguments), "capability": CAPABILITY_ECHO}


class ConformanceLoop:
    """Single-step loop proving only typed tool calls produce effects.

    Free text — including text that looks like commands, JSON or shell —
    is never parsed into dispatch; the sole effect path is
    ``tool_calls_in_order`` under the frozen capability table (§41.53).
    """

    def __init__(
        self,
        provider: DeterministicProvider,
        *,
        budget: TaskBudget,
        capabilities: Mapping[str, Any] | None = None,
    ) -> None:
        self._provider = provider
        self._budget = budget
        self._capabilities = {CAPABILITY_ECHO: echo_execute, **(capabilities or {})}
        self.effects: list[str] = []

    def run(self) -> dict[str, Any]:
        accounting = TurnAccounting(budget=self._budget)
        while True:
            accounting.begin_turn()
            response = self._provider.invoke({"turn": accounting.turns_used})
            issues = validate_response(response)
            if issues:
                raise StableError(
                    code=ErrorCode.INVALID_RESULT,
                    message="conformance response violates the loop contract",
                    details={"issues": list(issues)},
                )
            calls = tool_calls_in_order(response)
            if calls:
                for call in calls:
                    accounting.reserve_tool_call()
                    executor = self._capabilities.get(call.name)
                    if executor is None:
                        raise StableError(
                            code=ErrorCode.NOT_FOUND,
                            message="unknown capability in frozen surface",
                            details={"capability": call.name, "call_id": call.call_id},
                        )
                    executor({})
                    self.effects.append(call.name)
                continue
            result = terminal_result(response)
            return {
                "status": "SUCCEEDED",
                "result_truncated": result.result_truncated,
                "effects": tuple(self.effects),
            }
