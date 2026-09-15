"""Deterministic evaluator for ``deterministic-evaluation/v1`` (§41.43).

Pure application module: given a validated criteria document, frozen
evidence bundles (keyed by assertion kind), candidate artifact records
and the candidate package file map, produce assertion results and an
ALL_REQUIRED_PASS decision. Every assertion either observes its bundle
or resolves to UNKNOWN (which rejects); *within* an observed bundle a
missing value is FAIL — never a default of 0. The same inputs always
produce the same assertion results, decision and ``result_hash``
(AC-M42). An evaluator crash must never become ACCEPT, so
``evaluate_safely`` collapses any exception into a FAILED outcome.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..domain.canonical import canonical_json, sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.evolution import (
    CRITERIA_SCHEMA,
    assertion_result,
    decide,
    validate_criteria,
)
from .security_scan import findings_document, scan_package

__all__ = ["evaluate", "evaluate_safely"]


def _require_bundle(
    bundles: Mapping[str, Mapping[str, Any]], kind: str
) -> Mapping[str, Any] | None:
    bundle = bundles.get(kind)
    if bundle is None:
        return None
    if not isinstance(bundle, Mapping):
        return None
    return bundle


def _int_field(bundle: Mapping[str, Any], field: str) -> int | None:
    value = bundle.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _artifact_integrity(
    assertion: Mapping[str, Any],
    bundle: Mapping[str, Any] | None,
) -> bool | None:
    if bundle is None:
        return None
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        return False
    for record in artifacts.values():
        if not isinstance(record, Mapping):
            return False
        declared = record.get("declared_hash")
        observed = record.get("observed_hash")
        if not isinstance(declared, str) or not isinstance(observed, str):
            return False
        if declared != observed:
            return False
    return True


def _compatibility_report(
    assertion: Mapping[str, Any],
    bundle: Mapping[str, Any] | None,
) -> bool | None:
    if bundle is None:
        return None
    activatable = bundle.get("activatable")
    if not isinstance(activatable, bool):
        return False
    if assertion.get("require_activatable") and not activatable:
        return False
    return True


def _test_suite(
    assertion: Mapping[str, Any],
    bundle: Mapping[str, Any] | None,
) -> bool | None:
    if bundle is None:
        return None
    observed_suite = bundle.get("suite_artifact_id")
    if observed_suite != assertion.get("suite_artifact_id"):
        return False
    pass_rate = _int_field(bundle, "pass_rate_ppm")
    if pass_rate is None:
        return False
    return pass_rate >= int(assertion["required_pass_rate_ppm"])


def _budget(
    assertion: Mapping[str, Any],
    bundle: Mapping[str, Any] | None,
) -> bool | None:
    if bundle is None:
        return None
    wall_time = _int_field(bundle, "wall_time_us")
    if wall_time is None:
        return False
    if wall_time > int(assertion["max_wall_time_us"]):
        return False
    cost = _int_field(bundle, "cost_microunits")
    if cost is None:
        return False
    return cost <= int(assertion["max_cost_microunits"])


def _metric(
    assertion: Mapping[str, Any],
    bundle: Mapping[str, Any] | None,
) -> bool | None:
    if bundle is None:
        return None
    baseline = bundle.get("baseline_value")
    candidate = bundle.get("candidate_value")
    if not isinstance(baseline, (int, float)) or isinstance(baseline, bool):
        return False
    if not isinstance(candidate, (int, float)) or isinstance(candidate, bool):
        return False
    absolute = assertion.get("absolute_threshold")
    relative = assertion.get("relative_threshold")
    if absolute is None and relative is None:
        return False
    delta = abs(candidate - baseline)
    if absolute is not None:
        allowed = float(absolute)
        if relative is not None:
            allowed += abs(float(baseline)) * float(relative)
        scale = max(1.0, max(abs(float(baseline)), abs(float(candidate))))
        if (delta / scale) > 1e-9 and delta > allowed:
            return False
    return True


_EVALUATORS = {
    "artifact_integrity": _artifact_integrity,
    "compatibility_report": _compatibility_report,
    "test_suite": _test_suite,
    "budget": _budget,
    "metric": _metric,
}


def _security_policy(
    assertion: Mapping[str, Any], package_files: Mapping[str, bytes]
) -> tuple[bool, Mapping[str, Any]]:
    document = findings_document(scan_package(package_files))
    allow_high = int(assertion.get("allow_high_findings", 0))
    return document["high_count"] <= allow_high, {"scan": document}


def evaluate(
    criteria: Mapping[str, Any],
    evidence_bundles: Mapping[str, Mapping[str, Any]],
    package_files: Mapping[str, bytes],
) -> tuple[tuple[Any, ...], str, dict[str, Any]]:
    """Run every criteria assertion and return (results, decision, document).

    ``document`` carries the assertion results, the decision and a
    ``result_hash`` over exactly those inputs — the determinism anchor
    for the evaluation artifact (AC-M42).
    """

    issues = validate_criteria(criteria)
    if issues:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="criteria document is not well-formed",
            details={"issues": list(issues)},
        )

    results: list[Any] = []
    details_by_kind: dict[str, Mapping[str, Any]] = {}
    for assertion in criteria["assertions"]:
        kind = assertion["kind"]
        if kind == "security_policy":
            passed, details = _security_policy(assertion, package_files)
            details_by_kind[kind] = details
        else:
            bundle = _require_bundle(evidence_bundles, kind)
            passed = _EVALUATORS[kind](assertion, bundle)
        results.append(
            assertion_result(kind=kind, required=True, passed=passed, details={})
        )

    decision = decide(tuple(results))
    document: dict[str, Any] = {
        "schema": CRITERIA_SCHEMA,
        "decision_rule": "ALL_REQUIRED_PASS",
        "assertion_results": [
            {
                "kind": result.kind,
                "required": result.required,
                "status": result.status,
                "details": dict(result.details),
            }
            for result in results
        ],
        "decision": decision,
        "security_scan": details_by_kind.get("security_policy"),
    }
    result_hash = sha256_hex(canonical_json(document))
    document["result_hash"] = result_hash
    return tuple(results), decision, document


def evaluate_safely(
    criteria: Mapping[str, Any],
    evidence_bundles: Mapping[str, Mapping[str, Any]],
    package_files: Mapping[str, bytes],
) -> tuple[tuple[Any, ...] | None, str, dict[str, Any]]:
    """Evaluate; any crash becomes decision FAILED — never ACCEPT (§41.43).

    The store layer records FAILED as decision REJECT with body status
    FAILED, so a broken evaluator can never promote a candidate.
    """

    try:
        return evaluate(criteria, evidence_bundles, package_files)
    except Exception as exc:
        return (
            None,
            "FAILED",
            {
                "schema": CRITERIA_SCHEMA,
                "status": "FAILED",
                "error": type(exc).__name__,
                "detail": str(exc)[:200],
            },
        )
