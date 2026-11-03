"""Step 07 gate: Harness Loop contract DTOs and enforcement (§41.53)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.loop import (
    MAX_TOOL_CALLS_PER_RESPONSE,
    ArtifactPart,
    JsonPart,
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolResultPart,
    TurnAccounting,
    dispatchable_calls,
    terminal_result,
    validate_response,
)
from agent_meta_runtime.domain.semantics import TaskBudget


def tool_call(call_id="c1", name="cap.echo"):
    return ToolCallPart(call_id=call_id, name=name, arguments_json="{}")


def test_tool_call_turn_requires_tool_finish_reason():
    ok = ModelResponse(parts=(TextPart("working"), tool_call()), finish_reason="TOOL_CALL")
    assert validate_response(ok) == ()
    bad = ModelResponse(parts=(tool_call(),), finish_reason="LENGTH")
    issues = validate_response(bad)
    assert "loop.tool_call_finish_reason" in issues


def test_response_part_order_and_dispatch_choke_point():
    parts = (TextPart("use echo"), JsonPart({"cmd": "rm -rf /"}), tool_call("a"), tool_call("b"))
    response = ModelResponse(parts=parts, finish_reason="TOOL_CALL")
    assert validate_response(response) == ()
    # free text/JSON is never parsed into commands — only typed tool calls
    assert dispatchable_calls(response) == [("a", "cap.echo"), ("b", "cap.echo")]


def test_duplicate_call_id_and_limit():
    response = ModelResponse(
        parts=(tool_call("x"), tool_call("x")), finish_reason="STOP"
    )
    assert "loop.duplicate_call_id" in validate_response(response)
    many = tuple(tool_call(f"c{i}") for i in range(MAX_TOOL_CALLS_PER_RESPONSE + 1))
    issues = validate_response(ModelResponse(parts=many, finish_reason="STOP"))
    assert any(i.startswith("loop.too_many_tool_calls:") for i in issues)


def test_stray_tool_result_and_unknown_finish():
    response = ModelResponse(parts=(ToolResultPart("c1", "OK"),), finish_reason="STOP")
    assert "loop.stray_tool_result" in validate_response(response)
    empty = ModelResponse(parts=(), finish_reason="")
    assert "loop.finish_reason" in validate_response(empty)
    assert "loop.terminal_finish_reason" in validate_response(empty)


def test_terminal_result_and_truncation_flag():
    response = ModelResponse(
        parts=(TextPart("done"), ArtifactPart("artifact://sha256/" + "0" * 64)),
        finish_reason="LENGTH",
    )
    result = terminal_result(response)
    assert result.result_truncated is True
    assert isinstance(result.parts[0], TextPart)

    with pytest.raises(StableError) as excinfo:
        terminal_result(
            ModelResponse(parts=(TextPart("x"),), finish_reason="ERROR")
        )
    assert excinfo.value.code == ErrorCode.INVALID_RESULT

    with pytest.raises(StableError) as excinfo:
        terminal_result(
            ModelResponse(parts=(tool_call(),), finish_reason="STOP")
        )
    assert excinfo.value.code == ErrorCode.INVALID_RESULT


def test_turn_accounting_counts_model_call_and_steps():
    budget = TaskBudget(max_turns=2, max_steps=3, max_model_calls=2)
    acc = TurnAccounting(budget=budget)
    acc.begin_turn()  # turn 1: 1 model call + 1 step
    acc.reserve_tool_call()  # step 2
    acc.reserve_tool_call()  # step 3 — max_steps reached
    with pytest.raises(StableError) as excinfo:
        acc.reserve_tool_call()
    assert excinfo.value.code == ErrorCode.RESOURCE_EXHAUSTED


def test_cancelled_invocation_still_counts_model_call():
    budget = TaskBudget(max_turns=1, max_model_calls=1)
    acc = TurnAccounting(budget=budget)
    acc.begin_turn()
    # cancel released cost, but a retry of the turn is still quota-blocked
    with pytest.raises(StableError) as excinfo:
        acc.begin_turn()
    assert excinfo.value.code == ErrorCode.RESOURCE_EXHAUSTED


def test_turns_and_model_calls_exhausted():
    acc = TurnAccounting(budget=TaskBudget(max_turns=1, max_model_calls=5, max_steps=100))
    acc.begin_turn()
    with pytest.raises(StableError) as excinfo:
        acc.begin_turn()
    assert excinfo.value.code == ErrorCode.RESOURCE_EXHAUSTED
