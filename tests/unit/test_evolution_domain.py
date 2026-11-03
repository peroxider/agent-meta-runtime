"""Step 08.1 gate: Evolution domain DTOs and ChangeSet rules (§41.43)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.evolution import (
    CANDIDATE_TRUST_CLASSES,
    CHANGE_SET_OPERATIONS,
    CRITERIA_SCHEMA,
    ChangeSet,
    ChangeSetOperation,
    apply_change_set,
    assertion_result,
    decide,
    validate_change_set,
    validate_criteria,
)
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.domain.semantics import TaskBudget

BASELINE = {
    "schema": "composition/v1",
    "realm_id": "realm://main",
    "slots": {
        "echo": {"capability": "capability://echo", "artifact_id": "artifact://a"},
    },
    "policy": {"retry": "none"},
}


def _hash(value) -> str:
    return sha256_hex(canonical_json(value))


def op_replace(path, new_value, baseline=BASELINE):
    current, present = None, False
    node = baseline
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            break
        node = node[part]
        current, present = node, True
    return ChangeSetOperation(
        operation="REPLACE_ARTIFACT",
        target_path=path,
        expected_old_value_hash=_hash(current) if present else None,
        new_value=new_value,
    )


# ------------------------------------------------------------ change set --

def test_change_set_operation_registry_is_frozen_v1():
    assert CHANGE_SET_OPERATIONS == frozenset(
        {
            "ADD_SLOT",
            "REMOVE_SLOT",
            "REPLACE_ARTIFACT",
            "REWIRE",
            "BIND_STATE",
            "BIND_AUTHORITY",
            "SET_POLICY",
        }
    )
    assert CANDIDATE_TRUST_CLASSES == frozenset(
        {"trusted_candidate", "untrusted_candidate"}
    )


def test_validate_change_set_flags_duplicates_and_unknown_ops():
    change_set = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            ChangeSetOperation("ADD_SLOT", "slots.new", None, {}),
            ChangeSetOperation("ADD_SLOT", "slots.new", None, {}),
            ChangeSetOperation("TELEPORT", "slots.x", _hash({}), None),
        ),
        expected_serving_revision=1,
    )
    issues = validate_change_set(change_set)
    assert "changeset.duplicate_path:slots.new" in issues
    assert any(i.startswith("changeset.unknown_operation:") for i in issues)


def test_apply_requires_old_hash_for_existing_target():
    # None old hash means "target must be absent" — valid for new keys,
    # rejected when the target already exists
    create = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(ChangeSetOperation("SET_POLICY", "policy.new", None, 1),),
        expected_serving_revision=1,
    )
    assert apply_change_set(BASELINE, create)["policy"]["new"] == 1
    overwrite_existing = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(ChangeSetOperation("REMOVE_SLOT", "slots.echo", None, None),),
        expected_serving_revision=1,
    )
    with pytest.raises(StableError) as excinfo:
        apply_change_set(BASELINE, overwrite_existing)
    assert excinfo.value.details["reason_code"] == "OLD_HASH_REQUIRED"


def test_apply_change_set_clones_and_never_mutates_baseline():
    before = canonical_json(BASELINE)
    change_set = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            op_replace("slots.echo.artifact_id", "artifact://b"),
            ChangeSetOperation("ADD_SLOT", "slots.newer", None, {"capability": "capability://n"}),
        ),
        expected_serving_revision=1,
    )
    body = apply_change_set(BASELINE, change_set)
    assert body["slots"]["echo"]["artifact_id"] == "artifact://b"
    assert body["slots"]["newer"]["capability"] == "capability://n"
    assert canonical_json(BASELINE) == before  # baseline untouched


def test_apply_change_set_orders_by_path_and_rejects_stale_hash():
    # author order writes policy.zeta before policy.alpha; application is path-sorted
    change_set = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            ChangeSetOperation("SET_POLICY", "policy.zeta", None, 1),
            ChangeSetOperation("SET_POLICY", "policy.alpha", None, 2),
        ),
        expected_serving_revision=1,
    )
    body = apply_change_set(BASELINE, change_set)
    assert body["policy"] == {"retry": "none", "alpha": 2, "zeta": 1}

    stale = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            ChangeSetOperation(
                "REPLACE_ARTIFACT",
                "slots.echo.artifact_id",
                _hash("artifact://WRONG"),
                "artifact://b",
            ),
        ),
        expected_serving_revision=1,
    )
    with pytest.raises(StableError) as excinfo:
        apply_change_set(BASELINE, stale)
    assert excinfo.value.details["reason_code"] == "STALE_VALUE_HASH"


def test_apply_change_set_rejects_duplicate_path_and_bad_target():
    duplicate = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            ChangeSetOperation("SET_POLICY", "policy.a", None, 1),
            ChangeSetOperation("SET_POLICY", "policy.a", None, 2),
        ),
        expected_serving_revision=1,
    )
    with pytest.raises(StableError):
        apply_change_set(BASELINE, duplicate)
    missing_target = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(
            ChangeSetOperation(
                "REMOVE_SLOT", "slots.ghost", _hash({}), None
            ),
        ),
        expected_serving_revision=1,
    )
    with pytest.raises(StableError):
        apply_change_set(BASELINE, missing_target)
    add_existing = ChangeSet(
        change_set_id="changeset://1",
        proposal_id="proposal://1",
        baseline_id="composition://base",
        operations=(ChangeSetOperation("ADD_SLOT", "slots.echo", None, {}),),
        expected_serving_revision=1,
    )
    with pytest.raises(StableError):
        apply_change_set(BASELINE, add_existing)


# ------------------------------------------------------------- criteria --

CRITERIA = {
    "schema": CRITERIA_SCHEMA,
    "decision_rule": "ALL_REQUIRED_PASS",
    "assertions": [
        {"kind": "artifact_integrity"},
        {"kind": "compatibility_report", "require_activatable": True},
        {
            "kind": "test_suite",
            "suite_artifact_id": "artifact://sha256/" + "0" * 64,
            "required_pass_rate_ppm": 1000000,
        },
        {"kind": "security_policy", "allow_high_findings": 0},
        {"kind": "budget", "max_wall_time_us": 300000000, "max_cost_microunits": 0},
    ],
}


def test_criteria_v1_happy_document_validates_clean():
    assert validate_criteria(CRITERIA) == ()
    assert validate_criteria(TaskBudget()) != ()  # nonsense input flagged


def test_criteria_v1_flags_unknown_kinds_and_missing_fields():
    broken = {
        "schema": "deterministic-evaluation/v0",
        "decision_rule": "ANY_PASS",
        "assertions": [
            {"kind": "astrology"},
            {"kind": "test_suite", "required_pass_rate_ppm": 1},
            {"kind": "metric", "direction": "lower"},
        ],
    }
    issues = validate_criteria(broken)
    assert "criteria.schema" in issues
    assert "criteria.decision_rule" in issues
    assert "criteria.assertion_kind:0" in issues
    assert "criteria.test_suite_suite:1" in issues
    assert "criteria.metric_missing:baseline_value:2" in issues


def test_decision_is_all_required_pass():
    results = (
        assertion_result(kind="artifact_integrity", required=True, passed=True, details={}),
        assertion_result(kind="security_policy", required=True, passed=True, details={}),
    )
    assert decide(results) == "ACCEPT"
    fail = results + (
        assertion_result(kind="test_suite", required=True, passed=False, details={}),
    )
    assert decide(fail) == "REJECT"
    unknown = results + (
        assertion_result(kind="budget", required=True, passed=None, details={}),
    )
    assert decide(unknown) == "REJECT"
    optional_fail = results + (
        assertion_result(kind="metric", required=False, passed=False, details={}),
    )
    assert decide(optional_fail) == "ACCEPT"
