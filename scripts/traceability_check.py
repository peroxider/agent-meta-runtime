"""Traceability checker (§41.33/41.55, Runtime_09 step 6-7).

Parses the parent requirements document and the v0.1 scope-and-traceability
table and fails CI on any of:

- duplicate or unknown IDs on either side (strict set equality);
- a total other than the 218-ID v0.1 baseline;
- an invalid Scope/Status vocabulary;
- a ``Required`` row whose planned proof module does not exist under ``tests/``
  (``external://`` proofs belong to the Seed repository and are excluded from
  the Runtime verdict);
- an ``External-Seed`` row whose proof is not an ``external://`` URI;
- a feature report that advertises a ``Deferred`` or ``External-Seed`` row as
  implemented, or drops the explicit AC-M10/AC-M11 deferral.

Exit code 0 = all gates pass; 1 = at least one gate failed. Run:

    .venv/bin/python scripts/traceability_check.py [--feature-report PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PARENT_DOC = REPO_ROOT / "docs" / "Agent_Meta_Runtime_Requirements_Design_v0.1.md"
TRACEABILITY_DOC = REPO_ROOT / "docs" / "spec" / "v0.1-scope-and-traceability.md"
DEFAULT_FEATURE_REPORT = REPO_ROOT / "docs" / "feature-report-v0.1.md"

EXPECTED_TOTAL = 218

_SCOPES = frozenset(
    {"Required", "Deferred-M5", "Deferred-schema", "External-Seed"}
)
_STATUSES = frozenset({"SPECIFIED", "IMPLEMENTED", "VERIFIED"})

_HEADING_ID_RE = re.compile(
    r"^#{1,6}\s+((?:FR|AC)-[A-Z0-9]+(?:-[0-9A-Z]+)?)(?:\s*[：:（(].*)?\s*$"
)
_NFR_ROW_RE = re.compile(r"^\|\s*(NFR-M\d+)\s*\|")
_TABLE_ID_RE = re.compile(
    r"^\|\s*((?:FR|NFR|AC)-M[A-Z0-9]*(?:-[0-9A-Z]+)?)\s*\|"
)


def extract_parent_ids(text: str) -> tuple[list[str], list[str]]:
    """FR/AC ids are headings; NFR ids are table rows in the parent doc."""

    ids: list[str] = []
    duplicates: list[str] = []
    for line in text.splitlines():
        match = _HEADING_ID_RE.match(line) or _NFR_ROW_RE.match(line)
        if match is None:
            continue
        trace_id = match.group(1)
        if trace_id in ids:
            duplicates.append(trace_id)
        ids.append(trace_id)
    return ids, duplicates


def extract_table_rows(text: str) -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    duplicates: list[str] = []
    for line in text.splitlines():
        if not _TABLE_ID_RE.match(line):
            continue
        cells = [
            cell.strip().strip("`").strip()
            for cell in line.strip().strip("|").split("|")
        ]
        if len(cells) != 6:
            continue
        trace_id = cells[0]
        if any(row["id"] == trace_id for row in rows):
            duplicates.append(trace_id)
            continue
        rows.append(
            {
                "id": trace_id,
                "scope": cells[1],
                "owner": cells[2],
                "contract": cells[3],
                "proof": cells[4],
                "status": cells[5],
            }
        )
    return rows, duplicates


def check_feature_report(path: Path, rows: list[dict[str, str]]) -> list[str]:
    failures: list[str] = []
    if not path.is_file():
        return failures
    text = path.read_text(encoding="utf-8")
    lower = text.lower()
    blocked = [
        row["id"]
        for row in rows
        if row["scope"] in ("Deferred-M5", "Deferred-schema", "External-Seed")
    ]
    for trace_id in blocked:
        for line in text.splitlines():
            if trace_id not in line:
                continue
            if "implemented" in line.lower():
                failures.append(
                    f"feature report advertises {trace_id} as implemented:"
                    f" {line.strip()[:120]}"
                )
    for trace_id in ("AC-M10", "AC-M11"):
        if trace_id.lower() not in lower:
            failures.append(
                f"feature report does not explicitly mention deferred {trace_id}"
            )
    return failures


def run(feature_report: Path) -> list[str]:
    failures: list[str] = []

    parent_text = PARENT_DOC.read_text(encoding="utf-8")
    table_text = TRACEABILITY_DOC.read_text(encoding="utf-8")

    parent_ids, parent_dups = extract_parent_ids(parent_text)
    rows, table_dups = extract_table_rows(table_text)

    if parent_dups:
        failures.append(f"parent document duplicates: {sorted(set(parent_dups))}")
    if table_dups:
        failures.append(f"traceability table duplicates: {sorted(set(table_dups))}")

    parent_set = set(parent_ids)
    table_ids = [row["id"] for row in rows]
    table_set = set(table_ids)

    missing = sorted(parent_set - table_set)
    unknown = sorted(table_set - parent_set)
    if missing:
        failures.append(f"IDs in parent but not in table: {missing}")
    if unknown:
        failures.append(f"IDs in table but not in parent: {unknown}")

    if len(table_set) != EXPECTED_TOTAL:
        failures.append(
            f"traceability table holds {len(table_set)} unique IDs,"
            f" expected {EXPECTED_TOTAL}"
        )
    if len(rows) != len(table_set):
        failures.append(
            f"traceability table has {len(rows)} rows for {len(table_set)} unique IDs"
        )

    for row in rows:
        if row["scope"] not in _SCOPES:
            failures.append(f"{row['id']}: invalid scope {row['scope']!r}")
        if row["status"] not in _STATUSES:
            failures.append(f"{row['id']}: invalid status {row['status']!r}")
        proof = row["proof"]
        if row["scope"] == "External-Seed":
            if not proof.startswith("external://"):
                failures.append(
                    f"{row['id']}: External-Seed proof must be an external:// URI,"
                    f" got {proof!r}"
                )
            continue
        if not proof.startswith("tests/"):
            failures.append(
                f"{row['id']}: Runtime proof must live under tests/, got {proof!r}"
            )
            continue
        if not (REPO_ROOT / proof).is_file():
            failures.append(f"{row['id']}: planned proof missing: {proof}")

    failures.extend(check_feature_report(feature_report, rows))
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feature-report",
        type=Path,
        default=DEFAULT_FEATURE_REPORT,
        help="feature report to scan for deferred-advertising (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    failures = run(args.feature_report)
    if failures:
        print(f"traceability: {len(failures)} gate failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("traceability: OK (218-ID strict set equality holds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
