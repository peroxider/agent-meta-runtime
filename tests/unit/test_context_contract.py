"""Context policy conformance: frozen inputs, exact budgets and redaction."""

from dataclasses import replace
import json

import pytest

from agent_meta_runtime.sdk.context import (ContextSnapshot, FrozenContextSource,
    build_context_artifacts, build_projection_input)
from agent_meta_runtime.sdk.host import TaskEnvelope, TaskBudget
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex
from agent_meta_runtime.domain.context_projection import SECTION_DELIMITER, ladder_quotas
from agent_meta_runtime.domain.errors import StableError

UUID = "01900000-0000-7000-8000-000000000001"
COMPOSITION = "composition://" + UUID


def ref(raw):
    return "artifact://sha256/" + sha256_hex(raw)


def task_fixture(*, value=None, facts=(), budget=2048, overflow="REJECT", operations=(), tokenizer_descriptor=None):
    profile, artifacts = build_context_artifacts(input_schema={"type": "object", "required": ["value"],
        "properties": {"value": {"type": "string"}, "password": {"type": "string"}}, "additionalProperties": False},
        selected_operation_ids=[op["operation_id"] for op in operations], provider_id="test", budget_tokens=budget,
        input_overflow=overflow, tokenizer_descriptor=tokenizer_descriptor)
    artifacts = dict(artifacts)
    for operation in operations:
        for direction in ("input", "output"):
            schema = canonical_json({"type": "object", "properties": {"value": {"type": "string"}}})
            assert sha256_hex(schema) == operation[direction + "_schema_hash"]
            artifacts[ref(schema)] = schema
    constitution = canonical_json({"schema": "constitution/v1", "principles": ["explicit-authority"], "version": "1.0.0"})
    runtime = canonical_json({"schema": "context-runtime-summary/v1", "composition_id": COMPOSITION,
        "serving_revision": 1, "state_bindings": {}})
    sources = (FrozenContextSource("constitution", ref(constitution), constitution),
        FrozenContextSource("runtime", COMPOSITION, runtime), *(
            FrozenContextSource("fact", fact["fact_id"], canonical_json(fact)) for fact in facts))
    raw_input = canonical_json(value if value is not None else {"value": "hello"})
    surface = canonical_json({"operations": list(operations)})
    view = b"{}"
    return TaskEnvelope("task://" + UUID, "realm://main", "principal://service/" + UUID, "action://" + UUID, ref(raw_input), raw_input,
        COMPOSITION, 1, ref(surface), surface, (), TaskBudget(), 7, b"{}", None, b"{}", ref(view), view, b"{}",
        ContextSnapshot(profile, tuple(sorted(artifacts.items())), sources, True))


def section_json(projection, section):
    return json.loads(next(item.content for item in projection.sections if item.section_id == section))


def rewrite_resource(task, resource_key, transform):
    artifacts = dict(task.context.artifacts)
    profile = json.loads(artifacts[task.context.profile_artifact_id])
    document = json.loads(artifacts[profile[resource_key]])
    transformed = canonical_json(transform(document))
    profile[resource_key] = ref(transformed)
    artifacts[ref(transformed)] = transformed
    profile_raw = canonical_json(profile)
    artifacts[ref(profile_raw)] = profile_raw
    return replace(task, context=replace(task.context, profile_artifact_id=ref(profile_raw), artifacts=tuple(sorted(artifacts.items()))))


def fact(identity, *, seq, distance=0, secret="hidden", value="visible"):
    return {"schema": "context-fact/v1", "fact_id": identity, "seq": seq, "causal_distance": distance,
        "entity_id": "composition://test", "event_type": "example", "payload": {"secret": secret, "value": value}}


def test_context_has_five_ordered_sections_and_exact_delimiter_accounting():
    projection = build_projection_input(task_fixture())
    assert [s.section_id for s in projection.sections] == ["system", "task_input", "capability_schema", "state_summary", "facts"]
    assert all(s.token_count == len(s.content) for s in projection.sections)
    total = sum(s.token_count for s in projection.sections) + 4 * len(SECTION_DELIMITER)
    assert total <= projection.budget_tokens
    assert ladder_quotas(259) == (51, 77, 51, 38, 42)
    assert section_json(projection, "task_input") == {"value": "hello"}


def test_redaction_and_schema_normalization_precede_render_and_token_counts():
    first = task_fixture(value={"value": "Bearer abcdefghijklmnop", "password": "short", "unknown": "hidden"})
    second = task_fixture(value={"value": "Bearer different-token", "password": "long" * 100, "unknown": "other"})
    one, two = build_projection_input(first), build_projection_input(second)
    assert section_json(one, "task_input") == {"value": "[REDACTED]", "password": "[REDACTED]"}
    assert one.sections == two.sections
    assert one.source_refs != two.source_refs  # raw revision provenance remains exact


def test_fact_selection_is_distance_then_descending_sequence_then_identity():
    facts = [fact("fact://b", seq=8, distance=1), fact("fact://z", seq=1),
        fact("fact://a", seq=8, distance=1), fact("fact://c", seq=9, distance=1)]
    task = task_fixture(facts=facts, budget=4096)
    projection = build_projection_input(task)
    assert [f["fact_id"] for f in section_json(projection, "facts")] == ["fact://z", "fact://c", "fact://a", "fact://b"]
    assert all(f["payload"]["secret"] == "[REDACTED]" for f in section_json(projection, "facts"))
    reordered = replace(task, context=replace(task.context, sources=tuple(reversed(task.context.sources))))
    assert build_projection_input(reordered) == projection


def test_secret_lengths_cannot_change_fact_budget_selection():
    first = task_fixture(facts=[fact("fact://a", seq=1, secret="short")], budget=1024)
    second = task_fixture(facts=[fact("fact://a", seq=1, secret="x" * 50_000)], budget=1024)
    one, two = build_projection_input(first), build_projection_input(second)
    assert one.sections == two.sections
    assert section_json(one, "facts")[0]["fact_id"] == "fact://a"
    assert one.source_refs != two.source_refs


def test_frozen_context_is_identical_across_one_hundred_replays():
    task = task_fixture(facts=[fact("fact://a", seq=1)])
    expected = build_projection_input(task)
    assert all(build_projection_input(task) == expected for _ in range(100))


def test_input_overflow_rejects_unless_tail_truncation_is_explicit():
    value = {"value": "你好🌱" * 1000}
    with pytest.raises(StableError, match="truncation is not permitted"):
        build_projection_input(task_fixture(value=value, budget=1024))
    projection = build_projection_input(task_fixture(value=value, budget=1024, overflow="TAIL_TRUNCATE"))
    truncated = section_json(projection, "task_input")["value"]
    assert truncated and value["value"].startswith(truncated) and len(truncated) < len(value["value"])
    # The exact encoded prefix fills the available quota; Unicode is intact.
    input_section = projection.sections[1]
    capacity = sum(ladder_quotas(1024)[:2]) - projection.sections[0].token_count - len(SECTION_DELIMITER)
    assert input_section.token_count <= capacity
    assert len(canonical_json({"value": value["value"][:len(truncated) + 1]})) > capacity


def test_full_constitution_cannot_be_truncated_to_fit():
    task = task_fixture(budget=256)
    source = canonical_json({"schema": "constitution/v1", "principles": ["x" * 100]})
    task = replace(task, context=replace(task.context, sources=(FrozenContextSource("constitution", ref(source), source), task.context.sources[1])))
    with pytest.raises(StableError, match="required Context section"):
        build_projection_input(task)


@pytest.mark.parametrize("change", [lambda d: {**d, "tokenizer_id": "guessed/v1"}, lambda d: {**d, "version": True}])
def test_unavailable_exact_tokenizer_fails_before_provider(change):
    task = rewrite_resource(task_fixture(), "tokenizer_artifact_id", change)
    with pytest.raises(StableError, match="exact tokenizer"):
        build_projection_input(task)


def test_missing_frozen_resource_is_a_stable_failure():
    task = task_fixture()
    profile = json.loads(dict(task.context.artifacts)[task.context.profile_artifact_id])
    missing = profile["policy_artifact_id"]
    task = replace(task, context=replace(task.context, artifacts=tuple(item for item in task.context.artifacts if item[0] != missing)))
    with pytest.raises(StableError, match="resource is unavailable"):
        build_projection_input(task)


def test_malformed_redaction_patterns_fail_closed_with_stable_error():
    task = rewrite_resource(task_fixture(), "redaction_policy_artifact_id", lambda d: {**d, "patterns": [{}]})
    with pytest.raises(StableError, match="redaction minimum"):
        build_projection_input(task)


def test_fact_access_requirement_is_explicit_and_authorized():
    task = rewrite_resource(task_fixture(), "policy_artifact_id", lambda d: {**d, "require_facts": True})
    task = replace(task, context=replace(task.context, facts_available=False))
    with pytest.raises(StableError, match="not authorized") as exc:
        build_projection_input(task)
    assert exc.value.code == "AUTHORITY_DENIED"


def test_required_schema_contains_actual_full_operation_schemas():
    schema = canonical_json({"type": "object", "properties": {"value": {"type": "string"}}})
    operation = {"operation_id": "test.echo", "contract_version": "1.0.0", "description": "Echo",
        "effects": ["none"], "idempotency": "PURE", "retry_semantics": "NEVER", "required_permissions": [],
        "input_schema_hash": sha256_hex(schema), "output_schema_hash": sha256_hex(schema)}
    task = task_fixture(operations=[operation])
    selected = section_json(build_projection_input(task), "capability_schema")
    assert selected[0]["input_schema"] == json.loads(schema)
    assert selected[0]["output_schema"] == json.loads(schema)
    with pytest.raises(StableError, match="required Context section"):
        build_projection_input(task_fixture(operations=[operation], budget=512))


def test_snapshot_rejects_content_hash_tampering():
    task = task_fixture()
    artifacts = list(task.context.artifacts)
    artifacts[0] = (artifacts[0][0], b"tampered")
    with pytest.raises(ValueError, match="artifact snapshot"):
        replace(task.context, artifacts=tuple(artifacts))
