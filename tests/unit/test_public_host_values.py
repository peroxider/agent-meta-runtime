"""ADR 032: normalized live/replay values; not a bound-Host acceptance proof."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest
from agent_meta_runtime.sdk import ErrorCode, StableError
from agent_meta_runtime.sdk.host import (
    ArtifactPart, JsonPart, ModelResponse, ProviderUsage, TaskBudget, TaskEnvelope,
    TerminalResult, TextPart, ToolCallPart, ToolResultPart, decode_model_response,
    decode_terminal_result, encode_model_response, encode_terminal_result,
    ProviderAdapter, ProviderRequestPlan, ProviderTerminalResponse, HarnessAdapter,
)
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex


PROFILE = "artifact://sha256/" + "a" * 64
PLAN = {"model": "synthetic-model", "messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 8, "stream": False}


def test_public_provider_plan_and_terminal_expose_only_immutable_bounded_bytes():
    plan = ProviderRequestPlan(PROFILE, canonical_json(PLAN))
    terminal = ProviderTerminalResponse(PROFILE, b'{"complete":true}')
    assert not any(hasattr(value, field) for value in (plan, terminal) for field in (
        "credential", "credential_handle", "headers", "transport", "worker", "endpoint", "conn", "__dict__"))
    with pytest.raises(FrozenInstanceError):
        plan.body = b"{}"
    assert terminal.content == b'{"complete":true}'


@pytest.mark.parametrize("mutation", [
    {"endpoint": "https://forbidden.example"}, {"headers": {"Authorization": "forbidden"}},
    {"credential_handle": "credential://forbidden"}, {"stream": True}, {"max_tokens": True},
    {"max_tokens": 0}, {"messages": []}, {"model": "invalid model"}])
def test_public_provider_plan_cannot_select_transport_credentials_or_stream(mutation):
    with pytest.raises(ValueError):
        ProviderRequestPlan(PROFILE, canonical_json({**PLAN, **mutation}))


@pytest.mark.parametrize("body", [b"{}", b'{"model":1,"model":2}', b'{"model":NaN}', b'[]', bytearray(b"{}"), b" " * (1024*1024+1)])
def test_public_provider_plan_refuses_ambiguous_unbounded_or_mutable_body(body):
    with pytest.raises(ValueError):
        ProviderRequestPlan(PROFILE, body)


def test_provider_callbacks_cannot_silently_fallback_to_the_legacy_model_callback():
    async def callback(*args):
        pass
    provider = ProviderAdapter(lambda request: ProviderRequestPlan(PROFILE, canonical_json(PLAN)), lambda response: None)
    assert HarnessAdapter(callback, None, {}, callback, provider=provider).invoke_model is None
    with pytest.raises(ValueError):
        HarnessAdapter(callback, callback, {}, callback, provider=provider)
    with pytest.raises(ValueError):
        HarnessAdapter(callback, None, {}, callback)


def test_full_part_array_and_unknown_usage_survive_normalized_replay():
    response = ModelResponse((TextPart("first"), JsonPart({"nested": [{"a": 1}]}), ArtifactPart("artifact://sha256/" + "a" * 64), ToolCallPart("call-1", "cap.echo", '{"value":"hello"}')), "TOOL_CALL", ProviderUsage(None, 7, None))
    raw = encode_model_response(response)
    restored = decode_model_response(raw)
    assert encode_model_response(restored) == raw
    assert len(restored.parts) == 4
    assert restored.usage.input_tokens is None
    assert restored.usage.output_tokens == 7
    assert restored.usage.cost_microunits is None


def test_json_and_ordered_parts_are_immutable_snapshots():
    payload = {"nested": [{"value": "original"}]}
    parts = [TextPart("first"), JsonPart(payload)]
    response = ModelResponse(parts, "STOP")
    before = encode_model_response(response)
    payload["nested"][0]["value"] = "changed"
    parts.clear()
    assert encode_model_response(response) == before
    with pytest.raises(TypeError):
        response.parts[1].value["nested"][0]["value"] = "changed"


@pytest.mark.parametrize("response", [
    ModelResponse((), "STOP"), ModelResponse((TextPart(""),), "LENGTH"),
    ModelResponse((ToolResultPart("c1", "OK"),), "STOP"),
    ModelResponse((TextPart("ok"),), "ERROR"),
    ModelResponse((TextPart("ok"),), {}),
    ModelResponse((ArtifactPart("artifact://bad"),), "STOP"),
    ModelResponse((ToolCallPart("", "echo", "{}"),), "TOOL_CALL"),
    ModelResponse((ToolCallPart("c1", "echo", "[]"),), "TOOL_CALL"),
    ModelResponse((ToolCallPart("c1", "echo", '{"a":1,"a":2}'),), "TOOL_CALL"),
    ModelResponse((TextPart("ok"),), "STOP", ProviderUsage(input_tokens=-1)),
    ModelResponse((TextPart("ok"),), "STOP", ProviderUsage(cost_microunits=True)),
])
def test_invalid_provider_values_never_become_replayable_results(response):
    with pytest.raises(StableError) as error:
        encode_model_response(response)
    assert error.value.code == ErrorCode.INVALID_RESULT


@pytest.mark.parametrize("mutation", ["unknown_field", "unknown_kind", "bad_parts", "extra_usage", "noncanonical", "duplicate_field"])
def test_replay_rejects_unknown_fields_and_encoding_ambiguity(mutation):
    raw = encode_model_response(ModelResponse((TextPart("hi"),), "STOP"))
    body = json.loads(raw)
    if mutation == "unknown_field":
        body["extra"] = 1
    elif mutation == "unknown_kind":
        body["parts"][0]["kind"] = "shell"
    elif mutation == "bad_parts":
        body["parts"] = {}
    elif mutation == "extra_usage":
        body["usage"] = {"extra": 0}
    if mutation == "noncanonical":
        raw = json.dumps(body).encode()
    elif mutation == "duplicate_field":
        raw = raw[:-1] + b',"usage":null}'
    else:
        raw = canonical_json(body)
    with pytest.raises(StableError):
        decode_model_response(raw)


def test_length_terminal_preserves_all_content_in_order():
    result = TerminalResult((TextPart("one"), TextPart("two"), JsonPart({"answer": 42})), True)
    raw = encode_terminal_result(result)
    restored = decode_terminal_result(raw)
    assert restored.result_truncated
    assert [part.text for part in restored.parts[:2]] == ["one", "two"]
    assert encode_terminal_result(restored) == raw
    with pytest.raises(StableError):
        encode_terminal_result(TerminalResult((ToolCallPart("c1", "echo", "{}"),)))


def test_task_envelope_has_frozen_bindings_content_and_budget():
    source = b"task input"
    surface = b'{"format_version":1,"operations":[]}'
    states = [["state://example", "state-revision://example"]]
    task = TaskEnvelope(
        task_id="task://01900000-0000-7000-8000-000000000001", realm_id="realm://main",
        actor_id="principal://operator-root/01900000-0000-7000-8000-000000000002",
        root_action_id="action://01900000-0000-7000-8000-000000000003",
        input_artifact_id="artifact://sha256/" + sha256_hex(source), input_content=source,
        serving_composition_id="composition://01900000-0000-7000-8000-000000000004", serving_revision=1,
        capability_surface_artifact_id="artifact://sha256/" + sha256_hex(surface), capability_surface_content=surface,
        state_snapshot=states, budget=TaskBudget(), accepted_meta_revision=3,
        loop_policy_content=b"{}", deadline_at_us=None,
        composition_content=b"{}", acceptance_view_content=b"{}",
        acceptance_view_artifact_id="artifact://sha256/" + sha256_hex(b"{}"), harness_manifest_content=b"{}",
    )
    states[0][1] = "changed"
    assert task.state_snapshot[0][1] == "state-revision://example"
    with pytest.raises(FrozenInstanceError):
        task.serving_revision = 2
    with pytest.raises(ValueError, match="hash"):
        replace(task, input_content=b"tampered")
    with pytest.raises(ValueError, match="one frozen revision"):
        replace(task, state_snapshot=(("state://example", "a"), ("state://example", "b")))
