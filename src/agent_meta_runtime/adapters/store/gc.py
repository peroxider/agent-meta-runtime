"""Retention and garbage collection (§41.47.3).

GC marks come from a fixed schema registry — never free JSON scanning: every
registered artifact-id column, the registered JSON payload columns scanned
only for exact ``artifact://sha256/<hex>`` references, legal-hold ids from
the request, and backup pins (the CAS files sealed by successful backup
manifests). A GC plan is itself an Artifact recording the meta revision and
fact boundary; the sweep refuses to run when the revision advanced. Sweep
tombstones rows first (``artifact_blobs`` → QUARANTINED, ``artifacts`` →
MISSING) and only then moves CAS files to ``trash/<gc-id>/``; files are
deleted after 7 days only if no new reference appeared. Artifact rows are
never deleted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from ...domain.canonical import canonical_json, now_us, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7
from ..cas import FilesystemCas
from .backup import BACKUP_MANIFEST_NAME

__all__ = [
    "GC_MIN_AGE_US",
    "GC_TRASH_RETENTION_US",
    "apply_gc_quarantine",
    "build_gc_plan",
    "commit_gc_plan",
    "move_quarantined_to_trash",
    "purge_expired_trash",
    "validate_gc_plan",
]

GC_MIN_AGE_US = 24 * 60 * 60 * 1_000_000
GC_TRASH_RETENTION_US = 7 * 24 * 60 * 60 * 1_000_000

# Fixed mark registry: (table, column) pairs holding artifact ids.
_ARTIFACT_ID_COLUMNS: tuple[tuple[str, str], ...] = (
    ("epochs", "constitution_artifact_id"),
    ("epochs", "meta_root_artifact_id"),
    ("capabilities", "artifact_id"),
    ("capability_surfaces", "artifact_id"),
    ("harness_installations", "package_artifact_id"),
    ("harness_installations", "manifest_artifact_id"),
    ("state_revisions", "artifact_id"),
    ("state_revisions", "schema_id"),
    ("tasks", "input_artifact_id"),
    ("tasks", "capability_surface_artifact_id"),
    ("tasks", "result_artifact_id"),
    ("effect_intents", "payload_artifact_id"),
    ("invocations", "input_artifact_id"),
    ("invocations", "output_artifact_id"),
    ("context_projections", "policy_artifact_id"),
    ("context_projections", "rendered_artifact_id"),
    ("scratch_bindings", "source_artifact_id"),
    ("experiments", "criteria_artifact_id"),
    ("evidence", "artifact_id"),
    ("evaluations", "evaluator_artifact_id"),
    ("evaluations", "result_artifact_id"),
)

# Fixed JSON columns scanned only for exact artifact://sha256/<hex> refs.
_JSON_REF_COLUMNS: tuple[tuple[str, str], ...] = (
    ("facts", "payload_json"),
    ("compositions", "body_json"),
    ("worlds", "body_json"),
    ("evolution_objects", "body_json"),
    ("experiments", "body_json"),
    ("context_projections", "manifest_json"),
)

_ARTIFACT_REF_RE = re.compile(r"artifact://sha256/([0-9a-f]{64})")

_GC_PLAN_KIND = "GC_PLAN"


def _hex_of(artifact_id: Any) -> str | None:
    prefix = "artifact://sha256/"
    if isinstance(artifact_id, str) and artifact_id.startswith(prefix):
        candidate = artifact_id[len(prefix) :]
        if re.fullmatch(r"[0-9a-f]{64}", candidate):
            return candidate
    return None


def collect_marks(conn: sqlite3.Connection, extra_ids: tuple[str, ...] = ()) -> set[str]:
    """Compute the protected sha256 set from the fixed registry."""

    marks: set[str] = set()
    for table, column in _ARTIFACT_ID_COLUMNS:
        for (value,) in conn.execute(
            f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"
        ):
            hex_id = _hex_of(value)
            if hex_id:
                marks.add(hex_id)
    for table, column in _JSON_REF_COLUMNS:
        for (blob,) in conn.execute(f"SELECT {column} FROM {table}"):
            if blob is None:
                continue
            text = bytes(blob).decode("utf-8", errors="ignore")
            marks.update(_ARTIFACT_REF_RE.findall(text))
    for artifact_id in extra_ids:
        hex_id = _hex_of(artifact_id)
        if hex_id is None:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="legal hold entry is not an artifact id",
                details={"artifact_id": str(artifact_id)},
            )
        marks.add(hex_id)
    return marks


def _backup_pins(data_dir: Path, conn: sqlite3.Connection) -> tuple[set[str], int]:
    """CAS files sealed by successful backups stay pinned."""

    pins: set[str] = set()
    unresolved = 0
    rows = conn.execute(
        "SELECT result_json FROM operations WHERE kind = 'backup'"
        " AND status = 'SUCCEEDED'"
    ).fetchall()
    for (result_json,) in rows:
        try:
            result = json.loads(bytes(result_json).decode("utf-8"))
            destination = Path(str(result["destination"]))
            manifest = json.loads(
                (destination / BACKUP_MANIFEST_NAME).read_bytes().decode("utf-8")
            )
        except (OSError, ValueError, KeyError, TypeError):
            unresolved += 1
            continue
        for entry in manifest.get("files", []):
            relpath = str(entry.get("relpath", ""))
            if relpath.startswith("artifacts/"):
                pins.add(Path(relpath).name)
    return pins, unresolved


def build_gc_plan(
    conn: sqlite3.Connection,
    cas: FilesystemCas,
    data_dir: Path,
    *,
    realm_id: str,
    expected_meta_revision: int,
    legal_hold_artifact_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build a gc-plan Artifact document (§41.47.3)."""

    row = conn.execute(
        "SELECT current_meta_revision, next_seq, fact_head_hash FROM realms"
        " WHERE realm_id = ?",
        (realm_id,),
    ).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="unknown realm")
    meta_revision, next_seq, head_hash = int(row[0]), int(row[1]), row[2]
    if meta_revision != int(expected_meta_revision):
        raise StableError(
            code=ErrorCode.REVISION_CONFLICT,
            message="meta revision moved since the request",
            details={"expected": int(expected_meta_revision), "actual": meta_revision},
        )
    pins, unresolved = _backup_pins(Path(data_dir).resolve(), conn)
    marks = collect_marks(conn, tuple(legal_hold_artifact_ids)) | pins
    cutoff = now_us() - GC_MIN_AGE_US
    candidates: list[str] = []
    for artifact_id, created_at_us, integrity in conn.execute(
        "SELECT artifact_id, created_at_us, integrity_status FROM artifacts"
    ).fetchall():
        hex_id = _hex_of(artifact_id)
        if (
            hex_id is None
            or hex_id in marks
            or integrity != "VALID"
            or int(created_at_us) > cutoff
        ):
            continue
        candidates.append(artifact_id)
    plan = {
        "schema": "gc-plan/v1",
        "realm_id": realm_id,
        "meta_revision": meta_revision,
        "fact_boundary": {"last_seq": next_seq - 1, "head_hash": head_hash},
        "candidate_artifact_ids": sorted(candidates),
        "unresolved_backup_pins": unresolved,
        "generated_at_us": now_us(),
    }
    body = canonical_json(plan)
    storage_relpath = cas.put(body)
    return {
        "plan": plan,
        "plan_artifact_id": "artifact://sha256/" + sha256_hex(body),
        "storage_relpath": storage_relpath,
        "size_bytes": len(body),
    }


def commit_gc_plan(
    *,
    realm_id: str,
    plan_artifact_id: str,
    storage_relpath: str,
    size_bytes: int,
    candidate_count: int,
):
    """Mutator: register the gc-plan Artifact and record its Fact."""

    from .harness import _append_fact

    def mutator(txn) -> dict[str, Any]:
        txn._conn.execute(
            "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
            " schema_version, created_by, created_at_us, parents_json, manifest_json,"
            " integrity_status)"
            " VALUES (?, ?, 'application/json', ?, 1, ?, ?, x'5B5D', ?, 'VALID')",
            (
                plan_artifact_id,
                _GC_PLAN_KIND,
                size_bytes,
                txn._envelope.actor_id,
                txn.recorded_at_us,
                canonical_json(
                    {"storage_relpath": storage_relpath, "size_bytes": size_bytes}
                ),
            ),
        )
        fact_id = _append_fact(
            txn,
            entity_type="operations",
            entity_id=plan_artifact_id,
            event_type="gc_plan_recorded",
            payload={
                "plan_artifact_id": plan_artifact_id,
                "meta_revision": txn._conn.execute(
                    "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
                    (realm_id,),
                ).fetchone()[0],
                "candidate_count": candidate_count,
            },
        )
        return {"plan_artifact_id": plan_artifact_id, "fact_id": fact_id}

    return mutator


def _load_plan(
    conn: sqlite3.Connection, cas: FilesystemCas, plan_artifact_id: str
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT manifest_json, integrity_status FROM artifacts WHERE artifact_id = ?",
        (plan_artifact_id,),
    ).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="unknown gc-plan artifact")
    if row[1] != "VALID":
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="gc-plan artifact is not valid",
            details={"integrity_status": row[1]},
        )
    manifest = json.loads(bytes(row[0]).decode("utf-8"))
    body = cas.open_blob(
        manifest["storage_relpath"],
        plan_artifact_id.removeprefix("artifact://sha256/"),
        int(manifest["size_bytes"]),
    )
    plan = json.loads(bytes(body).decode("utf-8"))
    if plan.get("schema") != "gc-plan/v1":
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="unsupported gc-plan schema"
        )
    return plan


def validate_gc_plan(
    conn: sqlite3.Connection,
    cas: FilesystemCas,
    *,
    plan_artifact_id: str,
    realm_id: str,
) -> list[dict[str, Any]]:
    """Re-read the plan and resolve the still-sweepable candidates."""

    plan = _load_plan(conn, cas, plan_artifact_id)
    if plan["realm_id"] != realm_id:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="gc-plan belongs to another realm",
        )
    current = int(
        conn.execute(
            "SELECT current_meta_revision FROM realms WHERE realm_id = ?", (realm_id,)
        ).fetchone()[0]
    )
    plan_rev = int(plan["meta_revision"])
    if current < plan_rev:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="meta revision advanced since the plan; plan discarded",
            details={
                "reason_code": "GC_PLAN_STALE",
                "plan_revision": plan_rev,
                "current_revision": current,
            },
        )
    if current > plan_rev:
        # The plan's own recording command is allowed to have advanced the
        # revision by exactly one; any other interleaved mutation is not.
        if current != plan_rev + 1:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="meta revision advanced since the plan; plan discarded",
                details={
                    "reason_code": "GC_PLAN_STALE",
                    "plan_revision": plan_rev,
                    "current_revision": current,
                },
            )
        recording_txn = conn.execute(
            "SELECT transaction_id FROM meta_revisions WHERE realm_id = ?"
            " AND revision = ?",
            (realm_id, current),
        ).fetchone()
        plan_txn = conn.execute(
            "SELECT transaction_id FROM facts WHERE event_type = 'gc_plan_recorded'"
            " AND entity_id = ?",
            (plan_artifact_id,),
        ).fetchone()
        if (
            recording_txn is None
            or plan_txn is None
            or recording_txn[0] != plan_txn[0]
        ):
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="meta revision advanced since the plan; plan discarded",
                details={
                    "reason_code": "GC_PLAN_STALE",
                    "plan_revision": plan_rev,
                    "current_revision": current,
                },
            )
    plan_hex = _hex_of(plan_artifact_id)
    marks = collect_marks(conn)
    cutoff = now_us() - GC_MIN_AGE_US
    sweepable: list[dict[str, Any]] = []
    for artifact_id in plan["candidate_artifact_ids"]:
        hex_id = _hex_of(artifact_id)
        if hex_id is None or (hex_id in marks and hex_id != plan_hex):
            continue
        row = conn.execute(
            "SELECT created_at_us, integrity_status FROM artifacts"
            " WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None or row[1] != "VALID" or int(row[0]) > cutoff:
            continue
        blobs = conn.execute(
            "SELECT blob_id, storage_relpath FROM artifact_blobs"
            " WHERE artifact_id = ? AND status = 'ACTIVE'",
            (artifact_id,),
        ).fetchall()
        if not blobs:
            # artifact.put registers content only on artifacts (manifest_json);
            # artifact_blobs rows are the richer path when present.
            manifest = json.loads(
                bytes(
                    conn.execute(
                        "SELECT manifest_json FROM artifacts WHERE artifact_id = ?",
                        (artifact_id,),
                    ).fetchone()[0]
                ).decode("utf-8")
            )
            relpath = manifest.get("storage_relpath")
            if not relpath:
                continue
            blobs = [(None, str(relpath))]
        sweepable.append({"artifact_id": artifact_id, "blobs": blobs})
    return sweepable


def apply_gc_quarantine(entries: list[dict[str, Any]], *, operation_id: str):
    """Mutator: tombstone rows and append quarantine Facts."""

    from .harness import _append_fact

    def mutator(txn) -> dict[str, Any]:
        for entry in entries:
            artifact_id = entry["artifact_id"]
            for blob_id, _relpath in entry["blobs"]:
                if blob_id is not None:
                    txn._conn.execute(
                        "UPDATE artifact_blobs SET status = 'QUARANTINED'"
                        " WHERE blob_id = ?",
                        (blob_id,),
                    )
            txn._conn.execute(
                "UPDATE artifacts SET integrity_status = 'MISSING'"
                " WHERE artifact_id = ?",
                (artifact_id,),
            )
            _append_fact(
                txn,
                entity_type="operations",
                entity_id=operation_id,
                event_type="artifact_gc_quarantined",
                payload={
                    "reason_code": "GC_SWEEP",
                    # Recorded as a bare digest: the quarantine Fact documents
                    # the removal and must not re-pin the artifact through the
                    # artifact://sha256/ reference scan.
                    "artifact_sha256": artifact_id.removeprefix(
                        "artifact://sha256/"
                    ),
                    "operation_id": operation_id,
                },
            )
        return {"quarantined": [entry["artifact_id"] for entry in entries]}

    return mutator


def move_quarantined_to_trash(
    data_dir: Path,
    entries: list[dict[str, Any]],
) -> Path:
    """Move swept CAS files to trash/<gc-id>/ (same filesystem rename)."""

    data_dir = Path(data_dir).resolve()
    gc_id = new_uuid7()
    trash_dir = data_dir / "trash" / gc_id
    moved: list[dict[str, str]] = []
    for entry in entries:
        for _blob_id, storage_relpath in entry["blobs"]:
            source = data_dir / "artifacts" / storage_relpath
            if not source.is_file():
                continue
            target = trash_dir / storage_relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            moved.append(
                {
                    "artifact_id": entry["artifact_id"],
                    "storage_relpath": storage_relpath,
                }
            )
    trash_dir.mkdir(parents=True, exist_ok=True)
    (trash_dir / "metadata.json").write_text(
        json.dumps(
            {"gc_id": gc_id, "quarantined_at_us": now_us(), "entries": moved},
            sort_keys=True,
        )
    )
    return trash_dir


def purge_expired_trash(
    conn: sqlite3.Connection,
    data_dir: Path,
    *,
    retention_us: int = GC_TRASH_RETENTION_US,
) -> dict[str, Any]:
    """Delete trash files older than the retention window when unmarked."""

    data_dir = Path(data_dir).resolve()
    trash_root = data_dir / "trash"
    if not trash_root.is_dir():
        return {"purged_artifacts": [], "retained_dirs": 0}
    now = now_us()
    marks = collect_marks(conn)
    purged: list[str] = []
    retained = 0
    for entry_dir in sorted(trash_root.iterdir()):
        metadata_path = entry_dir / "metadata.json"
        if not metadata_path.is_file():
            continue
        try:
            metadata = json.loads(metadata_path.read_text())
        except ValueError:
            continue
        if now - int(metadata.get("quarantined_at_us", 0)) < retention_us:
            retained += 1
            continue
        remaining = False
        for item in metadata.get("entries", []):
            artifact_id = str(item.get("artifact_id", ""))
            hex_id = _hex_of(artifact_id)
            if hex_id is not None and hex_id in marks:
                remaining = True
                continue
            path = entry_dir / str(item.get("storage_relpath", ""))
            if path.is_file():
                path.unlink()
            conn.execute(
                "UPDATE artifact_blobs SET status = 'DELETED'"
                " WHERE storage_relpath = ? AND status = 'QUARANTINED'",
                (item.get("storage_relpath", ""),),
            )
            purged.append(artifact_id)
        conn.commit()
        if not remaining:
            shutil.rmtree(entry_dir, ignore_errors=True)
    return {"purged_artifacts": purged, "retained_dirs": retained}
