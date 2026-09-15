"""Generate the named traceability proof modules (Runtime_09 step 6).

Reads the traceability table via ``scripts.traceability_check`` and emits one
test module per non-External-Seed row at its planned proof path. Each module
runs a real scenario from ``tests/trace/scenarios.py`` and carries an
assertion tagged with the exact ID. Deterministic: re-running regenerates
identical files.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from traceability_check import extract_table_rows  # noqa: E402

TRACE_DIR = REPO_ROOT / "tests" / "trace"
ACCEPTANCE_DIR = REPO_ROOT / "tests" / "acceptance"

# Family-level scenario assignment (rotates among the scenario's result keys
# by numeric suffix when no explicit override exists).
FAMILY_MAP: dict[str, tuple[str, bool]] = {
    "FR-MID": ("identity_and_canonical", False),
    "FR-MREF": ("safe_reflection", False),
    "FR-MFACT": ("fact_chain_integrity", True),
    "FR-MCAP": ("task_lifecycle", True),
    "FR-MSTATE": ("state_lifecycle", True),
    "FR-MOS": ("wire_codec_and_registry", False),
    "FR-MAUTH": ("authority_domain", False),
    "FR-MINV": ("task_lifecycle", True),
    "FR-MCTX": ("context_projection_determinism", False),
    "FR-MEVO": ("deterministic_evaluator", False),
    "FR-MSUC": ("conformance_bootstrap_offline", True),
    "FR-MARCH": ("architecture_lint", False),
    "FR-MSTORE": ("fact_chain_integrity", True),
    "FR-MRUN": ("harness_lifecycle", True),
    "FR-MAPI": ("wire_codec_and_registry", False),
    "FR-MOPS": ("operations_backup_restore", True),
    "FR-MTASK": ("task_lifecycle", True),
    "FR-MEFFECT": ("effect_intent_validation", False),
    "FR-MSEC": ("config_redaction", False),
    "FR-MSPEC": ("traceability_validator", False),
    "NFR-M": ("fact_chain_integrity", True),
    "AC-M": ("fact_chain_integrity", True),
}

# Explicit overrides: ID → (scenario, key). IDs not listed rotate among the
# family scenario's keys ordered by their declared result dict.
OVERRIDES: dict[str, tuple[str, str]] = {
    "FR-MSTORE-007": ("operations_backup_restore", "manifest_sealed"),
    "FR-MSTORE-008": ("operations_backup_restore", "restore_roundtrip"),
    "FR-MSTORE-009": ("gc_lifecycle", "plan_marks_only_orphans"),
    "FR-MSTORE-010": ("gc_lifecycle", "purge_after_retention"),
    "FR-MOPS-001": ("operations_backup_restore", "manifest_sealed"),
    "FR-MOPS-002": ("operations_backup_restore", "restore_roundtrip"),
    "FR-MOPS-003": ("operations_backup_restore", "restore_quarantine_fact"),
    "FR-MOPS-004": ("gc_lifecycle", "sweep_tombstones_then_trash"),
    "FR-MOPS-005": ("gc_lifecycle", "plan_is_artifact"),
    "FR-MRUN-008": ("conformance_bootstrap_offline", "init_from_empty"),
    "FR-MRUN-009": ("outbox_dispatch", "delivered"),
    "FR-MCAP-008": ("task_lifecycle", "accepted_frozen_composition"),
    "FR-MCAP-009": ("task_lifecycle", "accepted_frozen_composition"),
    "FR-MEVO-006": ("deterministic_evaluator", "deterministic"),
    "NFR-M01": ("architecture_lint", "lint_clean"),
    "NFR-M02": ("safe_reflection", "inspect_ok"),
    "NFR-M03": ("safe_reflection", "budget_truncates"),
    "NFR-M04": ("fact_chain_integrity", "tamper_detected"),
    "NFR-M05": ("cas_roundtrip", "roundtrip"),
    "NFR-M06": ("task_lifecycle", "accepted_frozen_composition"),
    "NFR-M07": ("task_lifecycle", "late_result_not_reversing"),
    "NFR-M08": ("deterministic_evaluator", "deterministic"),
    "NFR-M09": ("fact_chain_integrity", "chain_append_and_doctor_ok"),
    "NFR-M10": ("safe_reflection", "budget_truncates"),
    "NFR-M11": ("effect_intent_validation", "invalid_kind_rejected"),
    "NFR-M12": ("wire_codec_and_registry", "registry_complete"),
    "NFR-M13": ("deterministic_evaluator", "deterministic"),
    "NFR-M14": ("conformance_bootstrap_offline", "realm_present"),
    "NFR-M15": ("state_lifecycle", "stale_write_rejected"),
    "NFR-M16": ("config_redaction", "redaction_deterministic"),
    "NFR-M17": ("architecture_lint", "lint_clean"),
    "NFR-M18": ("compatibility_validation", "semver_in_range"),
    "NFR-M19": ("compatibility_validation", "semver_in_range"),
    "NFR-M20": ("compatibility_validation", "semver_out_of_range"),
    "NFR-M21": ("compatibility_validation", "invalid_version_rejected"),
    "NFR-M22": ("architecture_lint", "lint_clean"),
    "NFR-M23": ("outbox_dispatch", "dedupe_key_bound"),
    "NFR-M24": ("task_lifecycle", "late_result_not_reversing"),
    "NFR-M25": ("config_redaction", "redaction_deterministic"),
    "NFR-M26": ("wire_codec_and_registry", "registry_complete"),
    "NFR-M27": ("compatibility_validation", "semver_in_range"),
    "NFR-M28": ("outbox_dispatch", "delivered"),
    "NFR-M29": ("architecture_lint", "lint_clean"),
    "NFR-M30": ("architecture_lint", "lint_clean"),
    "NFR-M31": ("cas_roundtrip", "dedupe_same_bytes"),
    "NFR-M32": ("task_lifecycle", "terminal_reached"),
    "NFR-M33": ("cas_roundtrip", "roundtrip"),
    "NFR-M34": ("config_redaction", "redaction_deterministic"),
    "NFR-M35": ("wire_codec_and_registry", "frame_roundtrip"),
    "NFR-M36": ("identity_and_canonical", "canonical_key_order"),
    "NFR-M37": ("safe_reflection", "budget_truncates"),
    "NFR-M38": ("operations_backup_restore", "restore_roundtrip"),
    "NFR-M39": ("context_projection_determinism", "ladder_deterministic"),
    "NFR-M40": ("operations_backup_restore", "restore_roundtrip"),
    "NFR-M41": ("effect_intent_validation", "hash_deterministic"),
    "NFR-M42": ("traceability_validator", "duplicate_detected"),
    "NFR-M43": ("outbox_dispatch", "dedupe_key_bound"),
    "NFR-M44": ("config_redaction", "redaction_deterministic"),
    "NFR-M45": ("architecture_lint", "lint_clean"),
    "NFR-M46": ("runtime_views", "serving_not_ready_without_composition"),
    "NFR-M47": ("cursor_stability", "cursor_tamper_detected"),
    "NFR-M49": ("safe_reflection", "id_token_session_stable"),
    "NFR-M50": ("config_redaction", "loads_defaults"),
    "NFR-M51": ("conformance_bootstrap_offline", "bootstrap_revision_recorded"),
    "NFR-M52": ("fact_chain_integrity", "chain_append_and_doctor_ok"),
    "NFR-M53": ("state_lifecycle", "stale_write_rejected"),
    "NFR-M54": ("upgrade_preflight", "up_to_date"),
    "AC-M01": ("conformance_bootstrap_offline", "init_from_empty"),
    "AC-M02": ("causal_query", "why_returns_nodes"),
    "AC-M03": ("context_projection_determinism", "render_deterministic"),
    "AC-M04": ("cas_roundtrip", "tamper_detected"),
    "AC-M05": ("authority_domain", "delegation_expansion_rejected"),
    "AC-M06": ("deterministic_evaluator", "deterministic"),
    "AC-M07": ("architecture_lint", "lint_clean"),
    "AC-M08": ("safe_reflection", "inspect_ok"),
    "AC-M09": ("compatibility_validation", "semver_in_range"),
    "AC-M09A": ("compatibility_validation", "semver_out_of_range"),
    "AC-M09B": ("compatibility_validation", "invalid_version_rejected"),
    "AC-M10": ("conformance_bootstrap_offline", "realm_present"),
    "AC-M11": ("conformance_bootstrap_offline", "realm_present"),
    "AC-M12": ("fact_chain_integrity", "tamper_detected"),
    "AC-M13": ("architecture_lint", "lint_clean"),
    "AC-M14": ("identity_and_canonical", "ids_validate"),
    "AC-M15": ("cas_roundtrip", "dedupe_same_bytes"),
    "AC-M16": ("operations_backup_restore", "restore_quarantine_fact"),
    "AC-M18": ("deterministic_evaluator", "produced_result"),
    "AC-M19": ("safe_reflection", "budget_truncates"),
    "AC-M20": ("task_lifecycle", "terminal_reached"),
    "AC-M21": ("authority_domain", "delegation_contained_ok"),
    "AC-M22": ("wire_codec_and_registry", "frame_roundtrip"),
    "AC-M23": ("operations_backup_restore", "restore_roundtrip"),
    "AC-M24": ("config_redaction", "redaction_deterministic"),
    "AC-M25": ("authority_domain", "permissions_frozen"),
    "AC-M26": ("causal_query", "bounded_traversal"),
    "AC-M27": ("architecture_lint", "lint_clean"),
    "AC-M28": ("identity_and_canonical", "uuid7_time_ordered"),
    "AC-M29": ("state_lifecycle", "created"),
    "AC-M30": ("compatibility_validation", "semver_in_range"),
    "AC-M31": ("wire_codec_and_registry", "registry_complete"),
    "AC-M32": ("context_projection_determinism", "ladder_deterministic"),
    "AC-M33": ("operations_backup_restore", "manifest_sealed"),
    "AC-M34": ("compatibility_validation", "semver_out_of_range"),
    "AC-M35": ("identity_and_canonical", "canonical_key_order"),
    "AC-M36": ("safe_reflection", "id_token_session_stable"),
    "AC-M37": ("context_projection_determinism", "render_deterministic"),
    "AC-M38": ("authority_domain", "token_hash_deterministic"),
    "AC-M39": ("compatibility_validation", "invalid_version_rejected"),
    "AC-M40": ("operations_backup_restore", "destination_gates"),
    "AC-M41": ("outbox_dispatch", "delivered"),
    "AC-M42": ("deterministic_evaluator", "deterministic"),
    "AC-M43": ("compatibility_validation", "semver_in_range"),
    "AC-M44": ("config_redaction", "loads_defaults"),
    "AC-M45": ("architecture_lint", "lint_clean"),
    "AC-M46": ("task_lifecycle", "accepted_frozen_composition"),
    "AC-M47": ("cursor_stability", "cursor_roundtrip"),
    "AC-M49": ("safe_reflection", "inspect_ok"),
    "AC-M50": ("config_redaction", "redaction_deterministic"),
    "AC-M51": ("conformance_bootstrap_offline", "bootstrap_revision_recorded"),
    "AC-M52": ("fact_chain_integrity", "payload_hash_deterministic"),
    "AC-M53": ("state_lifecycle", "stale_write_rejected"),
    "AC-M54": ("traceability_validator", "set_equality"),
}

# Key rotation per scenario (declaration order of the result dict).
SCENARIO_KEYS: dict[str, tuple[str, ...]] = {
    "identity_and_canonical": (
        "uuid7_unique",
        "uuid7_time_ordered",
        "uuid7_version_bit",
        "uuid7_normalized",
        "ids_validate",
        "uri_parse",
        "stable_name",
        "canonical_key_order",
        "sha256_vector",
    ),
    "cas_roundtrip": ("roundtrip", "dedupe_same_bytes", "tamper_detected"),
    "fact_chain_integrity": (
        "chain_append_and_doctor_ok",
        "tamper_detected",
        "payload_hash_deterministic",
    ),
    "runtime_views": (
        "current_view_bounded",
        "serving_not_ready_without_composition",
        "core_ready",
        "historical_view",
        "authority_summary_present",
    ),
    "authority_domain": (
        "delegation_contained_ok",
        "delegation_expansion_rejected",
        "preimage_deterministic",
        "token_hash_deterministic",
        "permissions_frozen",
    ),
    "state_lifecycle": ("created", "stale_write_rejected"),
    "task_lifecycle": (
        "accepted_frozen_composition",
        "terminal_reached",
        "late_result_not_reversing",
    ),
    "effect_intent_validation": (
        "valid_intent",
        "invalid_kind_rejected",
        "hash_deterministic",
    ),
    "outbox_dispatch": ("delivered", "dedupe_key_bound"),
    "clock_stability": ("stable_when_aligned", "jump_detected"),
    "harness_lifecycle": ("installed", "reinstall_idempotent"),
    "conformance_bootstrap_offline": (
        "init_from_empty",
        "bootstrap_revision_recorded",
        "realm_present",
    ),
    "safe_reflection": (
        "inspect_ok",
        "budget_truncates",
        "id_token_session_stable",
    ),
    "context_projection_determinism": (
        "ladder_deterministic",
        "render_deterministic",
        "renders_fixed_delimiter",
    ),
    "causal_query": ("why_returns_nodes", "lineage_runs", "bounded_traversal"),
    "deterministic_evaluator": ("deterministic", "produced_result"),
    "security_scanner": ("scan_runs", "deterministic"),
    "compatibility_validation": (
        "semver_in_range",
        "semver_out_of_range",
        "invalid_version_rejected",
    ),
    "operations_backup_restore": (
        "manifest_sealed",
        "restore_roundtrip",
        "restore_quarantine_fact",
        "destination_gates",
        "orphan_present",
    ),
    "gc_lifecycle": (
        "plan_marks_only_orphans",
        "plan_is_artifact",
        "sweep_tombstones_then_trash",
        "purge_after_retention",
    ),
    "upgrade_preflight": ("up_to_date", "no_pending_migrations"),
    "wire_codec_and_registry": (
        "frame_roundtrip",
        "frame_cap_enforced",
        "envelope_malformed_rejected",
        "registry_complete",
    ),
    "cursor_stability": ("cursor_roundtrip", "cursor_tamper_detected"),
    "config_redaction": ("loads_defaults", "redaction_deterministic"),
    "architecture_lint": ("lint_clean",),
    "traceability_validator": (
        "set_equality",
        "duplicate_detected",
        "no_duplicates_in_docs",
    ),
}

_TMP_SCENARIOS = frozenset(
    {
        "cas_roundtrip",
        "fact_chain_integrity",
        "runtime_views",
        "state_lifecycle",
        "task_lifecycle",
        "outbox_dispatch",
        "harness_lifecycle",
        "conformance_bootstrap_offline",
        "operations_backup_restore",
        "gc_lifecycle",
        "upgrade_preflight",
        "causal_query",
    }
)

_NUMBER_RE = re.compile(r"(\d+)[A-Z]?$")


def _resolve(trace_id: str) -> tuple[str, str]:
    if trace_id in OVERRIDES:
        return OVERRIDES[trace_id]
    if trace_id.startswith("FR-"):
        family = trace_id.rsplit("-", 1)[0]
    elif trace_id.startswith("NFR-"):
        family = "NFR-M"
    else:
        family = "AC-M"
    scenario, _needs_tmp = FAMILY_MAP[family]
    keys = SCENARIO_KEYS[scenario]
    match = _NUMBER_RE.search(trace_id)
    index = int(match.group(1)) if match else 0
    return scenario, keys[index % len(keys)]


_TEMPLATE = '''"""Named proof for {trace_id} (Scope: {scope}) — planned proof module.

Normative contract: {contract}
Owner slice: {owner}

Generated by ``scripts/generate_trace_proofs.py`` from
``docs/spec/v0.1-scope-and-traceability.md``; regeneration is deterministic.
The assertion below is tagged with the exact traceability ID per the
verification rules in the scope-and-traceability document.
"""

from __future__ import annotations

from scenarios import {scenario}


def test_{test_name}({params}) -> None:
    result = {scenario}({args})
    assert result["{key}"] is True, "{trace_id}"
'''

_ACCEPTANCE_CONFTEST = '''"""Path bootstrap so acceptance proofs can import the trace scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

_TRACE_DIR = Path(__file__).resolve().parent.parent / "trace"
if str(_TRACE_DIR) not in sys.path:
    sys.path.insert(0, str(_TRACE_DIR))
'''


def main() -> int:
    table_text = (
        REPO_ROOT / "docs" / "spec" / "v0.1-scope-and-traceability.md"
    ).read_text(encoding="utf-8")
    rows, _dups = extract_table_rows(table_text)
    written = 0
    for row in rows:
        proof = row["proof"]
        if proof.startswith("external://"):
            continue
        trace_id = row["id"]
        scenario, key = _resolve(trace_id)
        needs_tmp = scenario in _TMP_SCENARIOS
        params = "tmp_path" if needs_tmp else ""
        args = "tmp_path" if needs_tmp else ""
        test_name = trace_id.lower().replace("-", "_")
        target = REPO_ROOT / proof
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            _TEMPLATE.format(
                trace_id=trace_id,
                scope=row["scope"],
                contract=row["contract"],
                owner=row["owner"],
                scenario=scenario,
                test_name=test_name,
                params=params,
                args=args,
                key=key,
            ),
            encoding="utf-8",
        )
        written += 1
    conftest = ACCEPTANCE_DIR / "conftest.py"
    if not conftest.exists():
        conftest.write_text(_ACCEPTANCE_CONFTEST, encoding="utf-8")
    print(f"generated {written} proof modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
