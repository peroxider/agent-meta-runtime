"""Store integrity doctor (§41.35, AC-M52).

Recomputes the per-Realm fact chain from genesis (or from the latest
checkpoint), verifies payload hashes, migration chain, store identity and
CAS blob integrity. Any mismatch is an ``INTEGRITY_ERROR`` finding and must
hold readiness at false.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...domain.facts import GENESIS_FACT_HEAD, compute_fact_hash
from .connection import APPLICATION_ID, USER_VERSION
from .initializer import verify_migration_chain
from .migrations import MIGRATION_CHECKSUM

__all__ = ["DoctorReport", "run_integrity_doctor"]


@dataclass
class DoctorReport:
    findings: list[dict[str, str]] = field(default_factory=list)
    realms_checked: int = 0
    facts_checked: int = 0
    blobs_checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings

    def add(self, detail: str, **kwargs: Any) -> None:
        self.findings.append(
            {
                "code": "INTEGRITY_ERROR",
                "detail": detail,
                **{k: str(v) for k, v in kwargs.items()},
            }
        )


def _check_store_identity(conn: sqlite3.Connection, report: DoctorReport) -> None:
    application_id = conn.execute("PRAGMA application_id").fetchone()[0]
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if application_id != APPLICATION_ID:
        report.add("application_id mismatch", actual=application_id)
    if user_version != USER_VERSION:
        report.add("user_version mismatch", actual=user_version)
    row = conn.execute(
        "SELECT checksum FROM schema_migrations WHERE version = 1"
    ).fetchone()
    if row is None:
        report.add("schema_migrations missing version 1")
    elif row[0] != MIGRATION_CHECKSUM:
        report.add(
            "migration checksum drift",
            expected=MIGRATION_CHECKSUM,
            actual=row[0],
        )


def _check_fact_chain(conn: sqlite3.Connection, report: DoctorReport) -> None:
    for realm_id, head_hash in conn.execute(
        "SELECT realm_id, fact_head_hash FROM realms ORDER BY realm_id"
    ).fetchall():
        report.realms_checked += 1
        expected_prev = GENESIS_FACT_HEAD
        expected_seq = 1
        computed_head = GENESIS_FACT_HEAD
        rows = conn.execute(
            "SELECT seq, occurred_at_us, recorded_at_us, actor_id, action_id,"
            " transaction_id, entity_type, entity_id, event_type, schema_version,"
            " payload_json, payload_hash, prev_fact_hash, fact_hash"
            " FROM facts WHERE realm_id = ? ORDER BY seq",
            (realm_id,),
        ).fetchall()
        for row in rows:
            report.facts_checked += 1
            (
                seq,
                occurred_at_us,
                recorded_at_us,
                actor_id,
                action_id,
                transaction_id,
                entity_type,
                entity_id,
                event_type,
                schema_version,
                payload_json,
                payload_hash,
                prev_fact_hash,
                fact_hash,
            ) = row
            if seq != expected_seq:
                report.add(
                    "fact seq gap or disorder",
                    realm_id=realm_id,
                    expected=str(expected_seq),
                    actual=str(seq),
                )
                expected_seq = seq
            if prev_fact_hash != expected_prev:
                report.add(
                    "prev_fact_hash mismatch (chain break or swap)",
                    realm_id=realm_id,
                    seq=str(seq),
                )
            if hashlib.sha256(payload_json).hexdigest() != payload_hash:
                report.add("payload_hash mismatch", realm_id=realm_id, seq=str(seq))
            computed = compute_fact_hash(
                prev_fact_hash,
                realm_id=realm_id,
                seq=seq,
                occurred_at_us=occurred_at_us,
                recorded_at_us=recorded_at_us,
                actor_id=actor_id,
                action_id=action_id,
                transaction_id=transaction_id,
                entity_type=entity_type,
                entity_id=entity_id,
                event_type=event_type,
                schema_version=schema_version,
                payload_hash=payload_hash,
            )
            if computed != fact_hash:
                report.add(
                    "fact_hash mismatch (row tampered)",
                    realm_id=realm_id,
                    seq=str(seq),
                )
            expected_prev = fact_hash
            computed_head = fact_hash
            expected_seq += 1
        if head_hash != computed_head:
            report.add(
                "realms.fact_head_hash mismatch",
                realm_id=realm_id,
                expected=computed_head,
                actual=head_hash,
            )


def _check_cas_blobs(
    conn: sqlite3.Connection, cas_root: Path, report: DoctorReport
) -> None:
    from ..cas import FilesystemCas

    cas = FilesystemCas(cas_root)
    blobs = conn.execute(
        "SELECT b.blob_id, b.storage_relpath, b.size_bytes, b.storage_class, b.status,"
        " e.ciphertext_hash FROM artifact_blobs b"
        " LEFT JOIN artifact_encryption e ON e.blob_id = b.blob_id"
        " WHERE b.status = 'ACTIVE'"
    ).fetchall()
    for blob_id, relpath, size_bytes, storage_class, _status, ciphertext_hash in blobs:
        report.blobs_checked += 1
        if storage_class == "ENCRYPTED_RESTRICTED":
            content_hash = ciphertext_hash
        elif "://sha256/" in blob_id:
            content_hash = blob_id.split("://sha256/", 1)[-1]
        else:
            content_hash = None
        if content_hash is None:
            report.add("blob id has no content hash", blob_id=blob_id)
            continue
        try:
            cas.open_blob(relpath, content_hash, size_bytes)
        except Exception as exc:  # noqa: BLE001 - doctor reports, never raises
            report.add(f"CAS blob verification failed: {exc}", blob_id=blob_id)

    # Bootstrap, public artifact.put and Host records can register their
    # ordinary content directly on artifacts, without artifact_blobs rows.
    # They require the same verification; a self-consistent backup-file hash
    # does not replace the immutable ArtifactId's content hash.
    inline = conn.execute(
        "SELECT a.artifact_id,a.size_bytes,a.manifest_json FROM artifacts a "
        "WHERE a.integrity_status='VALID' AND NOT EXISTS "
        "(SELECT 1 FROM artifact_blobs b WHERE b.artifact_id=a.artifact_id)"
    )
    for artifact_id, size_bytes, raw_manifest in inline:
        report.blobs_checked += 1
        try:
            manifest = json.loads(raw_manifest)
            if (not isinstance(artifact_id,str) or re.fullmatch(r'artifact://sha256/[0-9a-f]{64}',artifact_id) is None
                    or not isinstance(manifest,dict) or type(manifest.get('size_bytes')) is not int
                    or manifest['size_bytes'] != size_bytes or not isinstance(manifest.get('storage_relpath'),str)):
                raise ValueError('invalid inline Artifact storage metadata')
            cas.open_blob(manifest['storage_relpath'], artifact_id.rsplit('/',1)[1], size_bytes)
        except Exception:  # noqa: BLE001 - never echo untrusted metadata/content
            report.add('CAS inline Artifact verification failed',artifact_id=artifact_id)


def run_integrity_doctor(db_path: Path, cas_root: Path | None = None) -> DoctorReport:
    """Full-integrity scan; findings imply readiness must stay false."""

    report = DoctorReport()
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.execute("PRAGMA trusted_schema = OFF")
        _check_store_identity(conn, report)
        _check_fact_chain(conn, report)
        if cas_root is not None:
            _check_cas_blobs(conn, Path(cas_root), report)
    finally:
        conn.close()
    return report
