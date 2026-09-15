"""Step 08.3 gate: security scanner + deterministic evaluator (§41.43)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.application.evaluator import evaluate, evaluate_safely
from agent_meta_runtime.application.security_scan import (
    Finding,
    findings_document,
    scan_package,
)
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.evolution import CRITERIA_SCHEMA

CRITERIA = {
    "schema": CRITERIA_SCHEMA,
    "decision_rule": "ALL_REQUIRED_PASS",
    "assertions": [
        {"kind": "artifact_integrity"},
        {"kind": "compatibility_report", "require_activatable": True},
        {
            "kind": "test_suite",
            "suite_artifact_id": "artifact://suite",
            "required_pass_rate_ppm": 999000,
        },
        {"kind": "security_policy", "allow_high_findings": 0},
        {
            "kind": "budget",
            "max_wall_time_us": 300000000,
            "max_cost_microunits": 1000,
        },
        {
            "kind": "metric",
            "direction": "lower",
            "baseline_value": 100,
            "candidate_value": 90,
            "absolute_threshold": 50,
            "relative_threshold": 0.1,
            "sample_count": 3,
        },
    ],
}

CLEAN_FILES = {"pkg/__init__.py": b"import json\n", "pkg/mod.py": b"x = 1\n"}


def _bundles(**overrides):
    bundles = {
        "artifact_integrity": {
            "artifacts": {
                "artifact://a": {
                    "declared_hash": "h",
                    "observed_hash": "h",
                }
            }
        },
        "compatibility_report": {"activatable": True},
        "test_suite": {
            "suite_artifact_id": "artifact://suite",
            "pass_rate_ppm": 999500,
        },
        "budget": {"wall_time_us": 1000, "cost_microunits": 10},
        "metric": {"baseline_value": 100, "candidate_value": 90},
    }
    bundles.update(overrides)
    return bundles


def _statuses(results) -> dict[str, str]:
    return {r.kind: r.status for r in results}


# ------------------------------------------------------------- scanner --


def test_scan_flags_denied_dynamic_and_private_imports():
    files = {
        "pkg/bad.py": (
            b"import ctypes\n"
            b"import socket\n"
            b"import subprocess\n"
            b"import agent_meta_runtime.domain\n"
            b"value = eval('1+1')\n"
            b"import os\n"
            b"os.system('rm -rf /')\n"
            b"import sys\n"
            b"sys.path.append('/tmp')\n"
        ),
    }
    findings = scan_package(files)
    codes = {f.code for f in findings}
    assert {
        "denied_import",
        "private_runtime_import",
        "dynamic_execution",
        "process_spawn",
        "runtime_modification",
    } <= codes
    assert all(f.severity == "HIGH" for f in findings)


def test_scan_flags_native_binary_path_escape_and_relative_import():
    files = {
        "pkg/lib.so": b"\x7fELFbinary",
        "../escape.py": b"x = 1\n",
        "pkg/rel.py": b"from .. import other\n",
        "pkg/outer.py": b"import requests\n",
    }
    findings = scan_package(files, import_allowlist=("json",))
    codes = {f.code for f in findings}
    assert {"native_binary", "path_escape", "relative_import"} <= codes
    assert "non_allowlist_import" in codes  # MEDIUM: requests not allowlisted


def test_scan_flags_unparseable_source_and_case_conflict():
    files = {
        "pkg/broken.py": b"def (:\n",
        "pkg/Mod.py": b"x = 1\n",
        "pkg/mod.py": b"x = 2\n",
    }
    findings = scan_package(files)
    codes = {f.code for f in findings}
    assert "unparseable_source" in codes
    assert "case_conflict" in codes


def test_scan_clean_package_has_no_findings():
    assert scan_package(CLEAN_FILES) == ()


def test_findings_document_is_deterministic_and_counts_high():
    one = scan_package({"pkg/bad.py": b"import ctypes\n"})
    two = scan_package({"pkg/bad.py": b"import ctypes\n"})
    doc_a, doc_b = findings_document(one), findings_document(two)
    assert doc_a == doc_b
    assert doc_a["high_count"] == 1
    assert doc_a["scan_hash"] == sha256_hex(
        canonical_json(
            {
                "findings": doc_a["findings"],
                "high_count": doc_a["high_count"],
            }
        )
    )


# ------------------------------------------------------------ evaluator --


def test_evaluate_accepts_happy_path_and_is_deterministic():
    first = evaluate(CRITERIA, _bundles(), CLEAN_FILES)
    second = evaluate(CRITERIA, _bundles(), CLEAN_FILES)
    assert first[1] == "ACCEPT"
    assert first[0] == second[0]
    assert first[2]["result_hash"] == second[2]["result_hash"]
    assert _statuses(first[0]) == {
        "artifact_integrity": "PASS",
        "compatibility_report": "PASS",
        "test_suite": "PASS",
        "security_policy": "PASS",
        "budget": "PASS",
        "metric": "PASS",
    }


def test_evaluate_missing_evidence_is_unknown_which_rejects():
    bundles = _bundles()
    del bundles["test_suite"]
    results, decision, _document = evaluate(CRITERIA, bundles, CLEAN_FILES)
    assert _statuses(results)["test_suite"] == "UNKNOWN"
    assert decision == "REJECT"


def test_evaluate_security_scan_failure_rejects():
    tainted = dict(CLEAN_FILES)
    tainted["pkg/evil.py"] = b"import ctypes\n"
    _results, decision, document = evaluate(CRITERIA, _bundles(), tainted)
    assert decision == "REJECT"
    assert document["security_scan"]["scan"]["high_count"] == 1


def test_evaluate_missing_metric_values_fail_without_defaults():
    bundles = _bundles(metric={"baseline_value": 100})
    results, decision, _document = evaluate(CRITERIA, bundles, CLEAN_FILES)
    assert _statuses(results)["metric"] == "FAIL"
    assert decision == "REJECT"


def test_evaluate_budget_and_test_suite_failures_reject():
    bundles = _bundles(
        budget={"wall_time_us": 10**9, "cost_microunits": 1},
        test_suite={"suite_artifact_id": "artifact://suite", "pass_rate_ppm": 1},
    )
    results, decision, _document = evaluate(CRITERIA, bundles, CLEAN_FILES)
    statuses = _statuses(results)
    assert statuses["budget"] == "FAIL"
    assert statuses["test_suite"] == "FAIL"
    assert decision == "REJECT"


def test_evaluate_rejects_malformed_criteria():
    broken = dict(CRITERIA)
    broken["schema"] = "deterministic-evaluation/v0"
    with pytest.raises(Exception) as excinfo:
        evaluate(broken, _bundles(), CLEAN_FILES)
    assert "criteria" in str(excinfo.value)


def test_evaluate_safely_turns_crash_into_failed_not_accept():
    bad_criteria = {
        "schema": CRITERIA_SCHEMA,
        "decision_rule": "ALL_REQUIRED_PASS",
        "assertions": [{"kind": "test_suite", "suite_artifact_id": "artifact://s",
                        "required_pass_rate_ppm": "not-an-int"}],
    }
    results, decision, document = evaluate_safely(
        bad_criteria, {"test_suite": {"suite_artifact_id": "artifact://s",
                                      "pass_rate_ppm": 10}}, CLEAN_FILES
    )
    assert results is None
    assert decision == "FAILED"
    assert document["status"] == "FAILED"
    assert document["error"] in {"ValueError", "TypeError", "StableError"}
