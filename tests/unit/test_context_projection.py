"""Step 02 gate: deterministic context projection v1 (§41.12, §41.44.4)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.domain.context_projection import (
    SECTION_DELIMITER,
    BudgetLadder,
    CandidateFact,
    ProjectionManifest,
    Section,
    SourceRef,
    allocate_budget,
    projection_identity,
    render_sections,
    select_facts,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError


def _ladder(**needs):
    return BudgetLadder(needs=needs)


def test_ladder_allocates_caps_and_rolls_remainder():
    # Budget 1000: system cap 200, task_input 300, capability 200, state 150,
    # facts 150. Needs below caps leave remainder that rolls into facts.
    ladder = _ladder(system=100, task_input=300, capability_schema=50, state_summary=0, facts=100)
    alloc = allocate_budget(1000, ladder)
    assert alloc.granted["system"] == 100
    assert alloc.granted["task_input"] == 300
    assert alloc.granted["capability_schema"] == 50
    assert alloc.granted["state_summary"] == 0
    # facts took its 100 plus all 450 unused by the earlier segments.
    assert alloc.granted["facts"] == 550
    assert alloc.rejected is None


def test_required_full_overflow_rejects():
    ladder = _ladder(system=999, facts=0)
    alloc = allocate_budget(1000, ladder)
    assert alloc.rejected == "system"
    # task_input and state_summary are not required-full: they get clamped.
    ladder = _ladder(task_input=9999, facts=0)
    alloc = allocate_budget(1000, ladder)
    assert alloc.rejected is None
    assert alloc.granted["task_input"] == 300


def test_absent_segments_get_zero():
    alloc = allocate_budget(100, _ladder(facts=10))
    assert alloc.granted["system"] == 0
    assert alloc.granted["capability_schema"] == 0
    assert alloc.granted["facts"] == 100  # everything rolls down


def test_unknown_segment_rejected():
    with pytest.raises(ValueError):
        _ladder(custom_section=10)


def test_select_facts_ordering_and_dedup():
    facts = [
        CandidateFact("f-b", seq=5, causal_distance=1, entity_id="task://x", payload={}),
        CandidateFact("f-a", seq=5, causal_distance=1, entity_id="task://x", payload={}),
        CandidateFact("f-c", seq=9, causal_distance=0, entity_id="task://x", payload={}),
        CandidateFact("f-b", seq=5, causal_distance=1, entity_id="task://x", payload={}),
    ]
    selected = select_facts(facts, budget_tokens=100, tokens_per_fact=10)
    # distance asc, then seq desc, then fact_id asc; duplicate f-b dropped.
    assert [f.fact_id for f in selected] == ["f-c", "f-a", "f-b"]


def test_select_facts_budget_truncation():
    facts = [
        CandidateFact(f"f-{i}", seq=i, causal_distance=0, entity_id="task://x", payload={})
        for i in range(10)
    ]
    selected = select_facts(facts, budget_tokens=45, tokens_per_fact=10)
    assert len(selected) == 4  # floor(45/10)
    with pytest.raises(ValueError):
        select_facts(facts, budget_tokens=10, tokens_per_fact=0)
    with pytest.raises(ValueError):
        select_facts(facts, budget_tokens=-1, tokens_per_fact=10)


def _manifest(**overrides) -> ProjectionManifest:
    base = dict(
        projection_id="context://projection/01900000-0000-7000-8000-000000000001",
        policy_artifact_id="artifact://sha256/" + "a" * 64,
        composition_id="composition://01900000-0000-7000-8000-000000000002",
        meta_revision=3,
        source_refs=(SourceRef(kind="fact", ref="realm://main", content_hash="h"),),
        sections=(
            Section(
                section_id="system",
                renderer_artifact_id="artifact://sha256/" + "b" * 64,
                output_artifact_id="artifact://sha256/" + "c" * 64,
                token_count=10,
            ),
        ),
        redaction_policy_artifact_id="artifact://sha256/" + "d" * 64,
        tokenizer_id="tokenizer-v1",
        total_tokens=100,
        budget_tokens=200,
    )
    base.update(overrides)
    return ProjectionManifest(**base)


def test_manifest_identity_ignores_extensions():
    m1 = _manifest()
    m2 = _manifest(extensions={"x_note": "anything"})
    assert m1.identity_hash() == m2.identity_hash()
    assert projection_identity(m1) == projection_identity(m2)


def test_manifest_rejects_over_budget_and_bad_ids():
    with pytest.raises(StableError) as excinfo:
        _manifest(total_tokens=300, budget_tokens=200)
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION
    with pytest.raises(ValueError):
        _manifest(projection_id="context://projection/not-a-uuid")
    with pytest.raises(ValueError):
        _manifest(extensions={"note": "missing x_ prefix"})


def test_render_sections_uses_fixed_delimiter():
    assert render_sections([b"a", b"b", b"c"]) == b"a" + SECTION_DELIMITER + b"b" + SECTION_DELIMITER + b"c"
    assert render_sections([]) == b""
    assert render_sections([b"only"]) == b"only"


def test_projection_is_deterministic():
    facts = [
        CandidateFact("f-1", seq=1, causal_distance=0, entity_id="task://x", payload={}),
        CandidateFact("f-2", seq=2, causal_distance=1, entity_id="task://x", payload={}),
    ]
    ladder = _ladder(system=10, facts=20)
    a1 = allocate_budget(200, ladder)
    a2 = allocate_budget(200, ladder)
    assert a1 == a2
    s1 = select_facts(facts, budget_tokens=20, tokens_per_fact=10)
    s2 = select_facts(list(reversed(facts)), budget_tokens=20, tokens_per_fact=10)
    assert s1 == s2
