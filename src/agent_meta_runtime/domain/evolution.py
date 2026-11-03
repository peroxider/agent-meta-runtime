"""Evolution v0 deterministic baseline domain (§41.43, FR-MEVO-001..006).

Pure domain: Proposal/ChangeSet/Candidate/World/Experiment/Evidence/
Evaluation DTOs, ChangeSet application (clones a new composition body —
the baseline is never modified) and ``deterministic-evaluation/v1``
criteria validation. Persisting objects, running experiments and taking
Promotion decisions live in the adapters/application layers; this module
only defines the shapes and the deterministic rules they must obey.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json, sha256_hex
from .errors import ErrorCode, StableError
from .semantics import TaskBudget

__all__ = [
    "ASSERTION_KINDS",
    "CHANGE_SET_OPERATIONS",
    "CANDIDATE_TRUST_CLASSES",
    "CRITERIA_SCHEMA",
    "DECISION_RULE",
    "EXPERIMENT_STATUSES",
    "AssertionResult",
    "Candidate",
    "ChangeSet",
    "ChangeSetOperation",
    "Evaluation",
    "Evidence",
    "Experiment",
    "Proposal",
    "World",
    "apply_change_set",
    "assertion_result",
    "decide",
    "validate_change_set",
    "validate_criteria",
]

CRITERIA_SCHEMA = "deterministic-evaluation/v1"
DECISION_RULE = "ALL_REQUIRED_PASS"

CHANGE_SET_OPERATIONS = frozenset(
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

CANDIDATE_TRUST_CLASSES = frozenset({"trusted_candidate", "untrusted_candidate"})

ASSERTION_KINDS = frozenset(
    {
        "artifact_integrity",
        "compatibility_report",
        "test_suite",
        "security_policy",
        "budget",
        "metric",
    }
)

EXPERIMENT_STATUSES = frozenset(
    {"PENDING", "RUNNING", "COMPLETED", "FAILED", "INVALID"}
)

EVALUATION_DECISIONS = frozenset({"ACCEPT", "REJECT", "FAILED"})


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    hypothesis: str
    source_evidence_ids: tuple[str, ...]
    target_composition_id: str
    proposer: str
    created_at_us: int


@dataclass(frozen=True, slots=True)
class ChangeSetOperation:
    """Tagged union entry; ``new_value`` is a JSON-able scalar/mapping."""

    operation: str
    target_path: str
    expected_old_value_hash: str | None
    new_value: Any


@dataclass(frozen=True, slots=True)
class ChangeSet:
    change_set_id: str
    proposal_id: str
    baseline_id: str
    operations: tuple[ChangeSetOperation, ...]
    expected_serving_revision: int


@dataclass(frozen=True, slots=True)
class Candidate:
    candidate_id: str
    change_set_id: str
    composition_id: str
    trust_class: str
    artifact_ids: tuple[str, ...]
    status: str


@dataclass(frozen=True, slots=True)
class World:
    """Frozen v1 field set (§41.43); ``network_policy`` is always DENY."""

    world_id: str
    backend_profile_hash: str
    fixture_artifact_ids: tuple[str, ...]
    state_snapshot_ids: tuple[str, ...]
    environment_allowlist: tuple[str, ...]
    network_policy: str
    credential_handles: tuple[str, ...]
    workspace_quota: Mapping[str, int]
    budget: TaskBudget
    seed: int
    replay_level: str


@dataclass(frozen=True, slots=True)
class Experiment:
    experiment_id: str
    candidate_id: str
    baseline_id: str
    world_id: str
    criteria_artifact_id: str
    budget: TaskBudget
    status: str
    created_at_us: int
    completed_at_us: int | None


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    experiment_id: str | None
    producer_action_id: str
    kind: str
    subject_id: str
    artifact_id: str
    observed_at_us: int


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """Deterministic outcome of one criteria assertion on frozen Evidence."""

    kind: str
    required: bool
    status: str  # PASS | FAIL | UNKNOWN
    details: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Evaluation:
    evaluation_id: str
    experiment_id: str
    evaluator_artifact_id: str
    evidence_ids: tuple[str, ...]
    assertion_results: tuple[AssertionResult, ...]
    decision: str  # ACCEPT | REJECT | FAILED
    created_at_us: int


# ------------------------------------------------------------ change set --


def _hash_value(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def validate_change_set(change_set: ChangeSet) -> tuple[str, ...]:
    """Static ChangeSet validation; returns sorted issue strings."""

    issues: list[str] = []
    paths: list[str] = []
    for index, op in enumerate(change_set.operations):
        if op.operation not in CHANGE_SET_OPERATIONS:
            issues.append(f"changeset.unknown_operation:{index}:{op.operation}")
        if not op.target_path or op.target_path.startswith("."):
            issues.append(f"changeset.bad_path:{index}")
            continue
        paths.append(op.target_path)
        if op.operation == "ADD_SLOT" and op.expected_old_value_hash is not None:
            issues.append(f"changeset.add_has_old_hash:{op.target_path}")
    duplicates = {p for p in paths if paths.count(p) > 1}
    for path in sorted(duplicates):
        issues.append(f"changeset.duplicate_path:{path}")
    if not isinstance(change_set.expected_serving_revision, int):
        issues.append("changeset.expected_serving_revision")
    return tuple(sorted(issues))


def _resolve(body: Mapping[str, Any], path: str) -> tuple[Any, bool]:
    """Return (value, present) walking dotted dict keys."""

    node: Any = body
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None, False
        node = node[part]
    return node, True


def _write_at(body: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node: dict[str, Any] = body
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def _remove_at(body: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    node: Any = body
    for part in parts[:-1]:
        if not isinstance(node, Mapping) or part not in node:
            return
        node = node[part]
    if isinstance(node, dict):
        node.pop(parts[-1], None)


def apply_change_set(baseline_body: Mapping[str, Any], change_set: ChangeSet) -> dict[str, Any]:
    """Apply operations to a deep copy of the baseline body (§41.43).

    Operations are applied in path-sorted order; the author order is kept
    on the ChangeSet for audit. The baseline mapping is never mutated and
    the returned body is a fresh ``composition/v1`` document. Any stale
    ``expected_old_value_hash`` or structural violation raises and leaves
    the baseline untouched.
    """

    issues = validate_change_set(change_set)
    if issues:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="change set is not well-formed",
            details={"issues": list(issues)},
        )
    if baseline_body.get("schema") != "composition/v1":
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="change set baseline must be a composition/v1 body",
        )
    body = copy.deepcopy(dict(baseline_body))
    ordered = sorted(change_set.operations, key=lambda op: op.target_path)
    for op in ordered:
        current, present = _resolve(body, op.target_path)
        if op.operation == "ADD_SLOT":
            if present:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="ADD_SLOT target already exists",
                    details={"target_path": op.target_path},
                )
            _write_at(body, op.target_path, op.new_value)
            continue
        if not present:
            if op.expected_old_value_hash is not None:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="stale expected old value hash",
                    details={
                        "reason_code": "STALE_VALUE_HASH",
                        "target_path": op.target_path,
                    },
                )
            _write_at(body, op.target_path, op.new_value)
            continue
        if op.expected_old_value_hash is None:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="existing target requires the expected old value hash",
                details={
                    "reason_code": "OLD_HASH_REQUIRED",
                    "target_path": op.target_path,
                },
            )
        if _hash_value(current) != op.expected_old_value_hash:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="stale expected old value hash",
                details={
                    "reason_code": "STALE_VALUE_HASH",
                    "target_path": op.target_path,
                },
            )
        if op.operation == "REMOVE_SLOT":
            _remove_at(body, op.target_path)
        else:
            _write_at(body, op.target_path, op.new_value)
    return body


# ------------------------------------------------------------- criteria --


def validate_criteria(document: Any) -> tuple[str, ...]:
    """Validate a ``deterministic-evaluation/v1`` criteria document."""

    issues: list[str] = []
    if not isinstance(document, Mapping):
        return ("criteria.not_a_mapping",)
    if document.get("schema") != CRITERIA_SCHEMA:
        issues.append("criteria.schema")
    if document.get("decision_rule") != DECISION_RULE:
        issues.append("criteria.decision_rule")
    assertions = document.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        issues.append("criteria.assertions")
        return tuple(sorted(issues))
    for index, assertion in enumerate(assertions):
        if not isinstance(assertion, Mapping) or assertion.get("kind") not in ASSERTION_KINDS:
            issues.append(f"criteria.assertion_kind:{index}")
            continue
        kind = assertion["kind"]
        if kind == "test_suite":
            if not assertion.get("suite_artifact_id"):
                issues.append(f"criteria.test_suite_suite:{index}")
            if not isinstance(assertion.get("required_pass_rate_ppm"), int):
                issues.append(f"criteria.test_suite_rate:{index}")
        elif kind == "security_policy":
            if not isinstance(assertion.get("allow_high_findings"), int):
                issues.append(f"criteria.security_allow_high:{index}")
        elif kind == "budget":
            if not isinstance(assertion.get("max_wall_time_us"), int):
                issues.append(f"criteria.budget_wall_time:{index}")
            if not isinstance(assertion.get("max_cost_microunits"), int):
                issues.append(f"criteria.budget_cost:{index}")
        elif kind == "compatibility_report":
            if not isinstance(assertion.get("require_activatable"), bool):
                issues.append(f"criteria.compatibility_activatable:{index}")
        elif kind == "metric":
            # Missing metric inputs are FAIL — no defaults of 0 (§41.43).
            for field in (
                "direction",
                "baseline_value",
                "candidate_value",
                "absolute_threshold",
                "relative_threshold",
                "sample_count",
            ):
                if assertion.get(field) is None:
                    issues.append(f"criteria.metric_missing:{field}:{index}")
    return tuple(sorted(issues))


def assertion_result(
    *, kind: str, required: bool, passed: bool | None, details: Mapping[str, Any]
) -> AssertionResult:
    """Build one deterministic assertion outcome (``None`` = UNKNOWN)."""

    status = "UNKNOWN" if passed is None else ("PASS" if passed else "FAIL")
    return AssertionResult(
        kind=kind,
        required=required,
        status=status,
        details=dict(details),
    )


def decide(results: tuple[AssertionResult, ...]) -> str:
    """ALL_REQUIRED_PASS: any required FAIL/UNKNOWN rejects (§41.43)."""

    for result in results:
        if result.required and result.status != "PASS":
            return "REJECT"
    return "ACCEPT"
