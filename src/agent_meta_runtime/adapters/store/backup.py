"""Backup, restore and upgrade preflight (§41.47, §41.47.2).

A backup is a daemon-exclusive quiesced snapshot: ``meta.db`` and
``backend/portable.db`` are copied through the SQLite backup API, durable
request markers and CAS blobs are hardlinked (or copied across devices),
and a JCS ``backup-manifest.json`` records versions, the fact boundary and
per-file SHA-256 hashes. Restore targets only a nonexistent/empty data
directory: every file is hash-verified from staging before atomic publish,
the store identity and full fact chain are re-verified, interrupted
operations are quarantined ``FAILED_RECOVERY`` and a
``backup_snapshot_restored`` Fact is appended. No merge restore exists.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ... import __version__
from ...domain.canonical import canonical_json, now_us
from ...domain.errors import ErrorCode, StableError
from ...domain.facts import compute_fact_hash
from ...domain.ids import new_uuid7
from ..cas import CHUNK_SIZE
from ..private_paths import require_private_path, secure_private_path
from .connection import APPLICATION_ID, USER_VERSION
from .doctor import run_integrity_doctor
from .initializer import verify_store_identity
from .migrations import MIGRATION_VERSION

__all__ = [
    "BACKUP_MANIFEST_NAME",
    "MANIFEST_VERSION",
    "create_backup",
    "default_backup_root",
    "preflight_upgrade",
    "restore_backup",
    "run_upgrade",
    "validate_backup_destination",
]

BACKUP_MANIFEST_NAME = "backup-manifest.json"
MANIFEST_VERSION = 1


@dataclass(frozen=True)
class BackupOutcome:
    destination: Path
    manifest: dict[str, Any]
    manifest_sha256: str


def default_backup_root(data_dir: Path) -> Path:
    return Path(data_dir).resolve().parent / "agent-meta-backups"


def validate_backup_destination(data_dir: Path, destination: Path | None) -> Path:
    """Resolve and validate the backup destination (§41.47.1)."""

    data_dir = Path(data_dir).resolve()
    if destination is None:
        destination = default_backup_root(data_dir) / f"backup-{now_us()}"
    dest = Path(destination)
    if not dest.is_absolute():
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="backup destination must be an absolute path",
            details={"destination": str(dest)},
        )
    if os.path.realpath(dest) != str(dest):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="backup destination must not contain symlink components",
            details={"destination": str(dest)},
        )
    resolved = dest.resolve()
    if resolved == data_dir or data_dir in resolved.parents:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="backup destination must be outside the data directory",
            details={"destination": str(resolved)},
        )
    if resolved.exists():
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="backup destination already exists",
            details={"destination": str(resolved)},
        )
    return resolved


def check_quiescent(conn: sqlite3.Connection, data_dir: Path) -> None:
    """Fail closed unless no live execution effects or Scratch remain."""

    problems: list[str] = []
    if conn.execute(
        "SELECT 1 FROM tasks WHERE status IN ('ACCEPTED','RUNNING') LIMIT 1"
    ).fetchone():
        problems.append("RUNNING_TASKS")
    if conn.execute(
        "SELECT 1 FROM invocations WHERE status IN ('CREATED','DISPATCHED','RUNNING')"
        " LIMIT 1"
    ).fetchone():
        problems.append("LIVE_INVOCATIONS")
    if conn.execute(
        "SELECT 1 FROM effect_intents WHERE status IN ('DISPATCHED','UNKNOWN') LIMIT 1"
    ).fetchone():
        problems.append("UNKNOWN_EFFECTS")
    if conn.execute(
        "SELECT 1 FROM execution_bindings WHERE status NOT IN"
        " ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT','QUARANTINED') LIMIT 1"
    ).fetchone():
        problems.append("LIVE_EXECUTIONS")
    if conn.execute(
        "SELECT 1 FROM scratch_sessions WHERE status IN ('STARTING','ACTIVE') LIMIT 1"
    ).fetchone():
        problems.append("LIVE_SCRATCH")
    portable_db = Path(data_dir) / "backend" / "portable.db"
    if portable_db.exists():
        ledger = sqlite3.connect(f"file:{portable_db}?mode=ro", uri=True)
        try:
            if ledger.execute(
                "SELECT 1 FROM requests WHERE state IN"
                " ('PREPARED','CLAIMED','RUNNING','UNKNOWN') LIMIT 1"
            ).fetchone():
                problems.append("LIVE_PORTABLE_REQUESTS")
        finally:
            ledger.close()
    if problems:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="runtime is not quiescent; backup refused",
            details={"reason_code": "RUNTIME_NOT_QUIESCENT", "problems": problems},
        )


def _realm_snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        "SELECT realm_id, epoch_id, current_meta_revision, next_seq, fact_head_hash"
        " FROM realms ORDER BY realm_id LIMIT 1"
    ).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="no realm")
    return {
        "realm_id": row[0],
        "epoch_id": row[1],
        "meta_revision": int(row[2]),
        "last_seq": int(row[3]) - 1,
        "fact_head_hash": row[4],
    }


def _copy_hashed(source: Path, target: Path, root: Path, files: list) -> None:
    digest = hashlib.sha256()
    size = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(source, "rb") as reader, open(target, "wb") as writer:
        while chunk := reader.read(CHUNK_SIZE):
            writer.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    files.append(
        {
            "relpath": target.relative_to(root).as_posix(),
            "size_bytes": size,
            "sha256": digest.hexdigest(),
        }
    )


def _link_or_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def create_backup(
    conn: sqlite3.Connection,
    data_dir: Path,
    destination: Path | None = None,
    *,
    expected_meta_revision: int | None = None,
) -> BackupOutcome:
    """Create a quiesced, manifest-sealed backup (§41.47.1)."""

    data_dir = Path(data_dir).resolve()
    dest = validate_backup_destination(data_dir, destination)
    check_quiescent(conn, data_dir)
    realm = _realm_snapshot(conn)
    if (
        expected_meta_revision is not None
        and realm["meta_revision"] != int(expected_meta_revision)
    ):
        raise StableError(
            code=ErrorCode.REVISION_CONFLICT,
            message="meta revision moved since the request",
            details={
                "expected": int(expected_meta_revision),
                "actual": realm["meta_revision"],
            },
        )

    dest.mkdir(parents=True, mode=0o700)
    secure_private_path(dest)
    files: list[dict[str, Any]] = []
    try:
        # 1. meta.db through the SQLite backup API (consistent snapshot).
        target = dest / "meta.db"
        snapshot = sqlite3.connect(target)
        try:
            conn.backup(snapshot)
        finally:
            snapshot.close()
        size, sha = _hash_file(target)
        files.append({"relpath": "meta.db", "size_bytes": size, "sha256": sha})

        # 2. portable.db plus its durable request markers (never live handles).
        portable_db = data_dir / "backend" / "portable.db"
        if portable_db.exists():
            source = sqlite3.connect(f"file:{portable_db}?mode=ro", uri=True)
            try:
                target = dest / "backend" / "portable.db"
                target.parent.mkdir(parents=True, exist_ok=True)
                snapshot = sqlite3.connect(target)
                try:
                    source.backup(snapshot)
                finally:
                    snapshot.close()
                markers = [
                    row[0]
                    for row in source.execute(
                        "SELECT DISTINCT request_relpath FROM requests"
                    ).fetchall()
                ]
            finally:
                source.close()
            size, sha = _hash_file(dest / "backend" / "portable.db")
            files.append(
                {"relpath": "backend/portable.db", "size_bytes": size, "sha256": sha}
            )
            for marker in markers:
                marker_path = data_dir / "backend" / marker
                if marker_path.is_file():
                    _copy_hashed(marker_path, dest / "backend" / marker, dest, files)

        # 3. Credential ciphertext/metadata retain explicit owner-only ACLs.
        keys_dir = data_dir / "keys"
        if keys_dir.is_dir():
            require_private_path(keys_dir)
            (dest / "keys").mkdir()
            secure_private_path(dest / "keys")
            for key_path in sorted(keys_dir.iterdir()):
                if key_path.is_file():
                    require_private_path(key_path)
                    _copy_hashed(key_path, dest / "keys" / key_path.name, dest, files)
                    secure_private_path(dest / "keys" / key_path.name)
            providers=keys_dir/'providers'
            if providers.exists() or providers.is_symlink() or providers.is_junction():
                require_private_path(providers)
                for realm_dir in sorted(providers.iterdir()):
                    if not realm_dir.is_dir() or re.fullmatch(r'[0-9a-f]{64}',realm_dir.name) is None:
                        raise StableError(code=ErrorCode.INTEGRITY_ERROR,message='Provider credential storage scope is invalid')
                    require_private_path(realm_dir)
                    target_dir=dest/'keys'/'providers'/realm_dir.name
                    target_dir.mkdir(parents=True,exist_ok=True)
                    secure_private_path(target_dir.parent); secure_private_path(target_dir)
                    for item in sorted(realm_dir.iterdir()):
                        if item.name.startswith('.provisioning-'):
                            continue  # unpublished, unreferenced native staging
                        if (not item.is_file() or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.(dpapi|key)',item.name) is None):
                            raise StableError(code=ErrorCode.INTEGRITY_ERROR,message='Provider credential item path is invalid')
                        require_private_path(item)
                        _copy_hashed(item,target_dir/item.name,dest,files)
                        secure_private_path(target_dir/item.name)

        # 4. CAS blobs: hardlink on the same volume, copy otherwise.
        artifacts_dir = data_dir / "artifacts"
        if artifacts_dir.is_dir():
            for dirpath, _dirnames, filenames in os.walk(artifacts_dir):
                for name in filenames:
                    source_path = Path(dirpath) / name
                    relpath = source_path.relative_to(data_dir)
                    _link_or_copy(source_path, dest / relpath)
                    size, sha = _hash_file(dest / relpath)
                    files.append(
                        {"relpath": relpath.as_posix(), "size_bytes": size, "sha256": sha}
                    )
        files.sort(key=lambda entry: entry["relpath"])

        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "created_at_us": now_us(),
            "runtime_version": __version__,
            "api_version": "agent_meta.public.v1",
            "application_id": APPLICATION_ID,
            "db_schema_version": USER_VERSION,
            "migration_version": MIGRATION_VERSION,
            "realm_id": realm["realm_id"],
            "epoch_id": realm["epoch_id"],
            "meta_revision": realm["meta_revision"],
            "fact_boundary": {
                "last_seq": realm["last_seq"],
                "head_hash": realm["fact_head_hash"],
            },
            "backend": {"portable_db": portable_db.exists()},
            "files": files,
        }
        manifest_bytes = canonical_json(manifest)
        (dest / BACKUP_MANIFEST_NAME).write_bytes(manifest_bytes)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return BackupOutcome(
        destination=dest,
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )


# -- restore ---------------------------------------------------------------------


def _verify_manifest(manifest: dict[str, Any], source_dir: Path) -> None:
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise StableError(
            code=ErrorCode.INTEGRITY_ERROR,
            message="backup manifest_version mismatch",
            details={"manifest_version": str(manifest.get("manifest_version"))},
        )
    if manifest.get("db_schema_version") != USER_VERSION or manifest.get(
        "migration_version"
    ) != MIGRATION_VERSION:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="backup schema version does not match this runtime",
            details={
                "backup_db_schema_version": str(manifest.get("db_schema_version")),
                "backup_migration_version": str(manifest.get("migration_version")),
            },
        )
    for entry in manifest.get("files", []):
        path = source_dir / str(entry["relpath"])
        if not path.is_file():
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="backup file missing",
                details={"relpath": entry["relpath"]},
            )
        size, sha = _hash_file(path)
        if size != int(entry["size_bytes"]) or sha != entry["sha256"]:
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="backup file hash mismatch",
                details={"relpath": entry["relpath"]},
            )


def _append_restore_fact(
    conn: sqlite3.Connection,
    realm_id: str,
    entity_id: str,
    *,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    """Offline fact append continuing the chain after restore (§41.47.1)."""

    row = conn.execute(
        "SELECT next_seq, fact_head_hash FROM realms WHERE realm_id = ?", (realm_id,)
    ).fetchone()
    seq, prev_hash = int(row[0]), row[1]
    payload_json = canonical_json(payload)
    payload_hash = hashlib.sha256(payload_json).hexdigest()
    occurred_at = recorded_at = now_us()
    actor_id = f"principal://service/{new_uuid7()}"
    transaction_id = f"txn://{new_uuid7()}"
    fact_hash = compute_fact_hash(
        prev_hash,
        realm_id=realm_id,
        seq=seq,
        occurred_at_us=occurred_at,
        recorded_at_us=recorded_at,
        actor_id=actor_id,
        action_id=None,
        transaction_id=transaction_id,
        entity_type="operations",
        entity_id=entity_id,
        event_type=event_type,
        schema_version=1,
        payload_hash=payload_hash,
    )
    fact_id = f"fact://{new_uuid7()}"
    conn.execute(
        "INSERT INTO facts(fact_id, realm_id, seq, occurred_at_us, recorded_at_us,"
        " actor_id, action_id, transaction_id, entity_type, entity_id, event_type,"
        " schema_version, payload_json, payload_hash, prev_fact_hash, fact_hash)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            fact_id,
            realm_id,
            seq,
            occurred_at,
            recorded_at,
            actor_id,
            None,
            transaction_id,
            "operations",
            entity_id,
            event_type,
            1,
            payload_json,
            payload_hash,
            prev_hash,
            fact_hash,
        ),
    )
    conn.execute(
        "UPDATE realms SET next_seq = ?, fact_head_hash = ? WHERE realm_id = ?",
        (seq + 1, fact_hash, realm_id),
    )
    return fact_id


def restore_backup(source_dir: Path, data_dir: Path) -> dict[str, Any]:
    """Restore a sealed backup into an empty data directory (§41.47.1)."""

    source_dir = Path(source_dir).resolve()
    data_dir = Path(data_dir).resolve()
    manifest_path = source_dir / BACKUP_MANIFEST_NAME
    if not manifest_path.is_file():
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="backup manifest missing",
            details={"source_dir": str(source_dir)},
        )
    try:
        manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise StableError(
            code=ErrorCode.INTEGRITY_ERROR, message="backup manifest is not JSON"
        ) from exc
    if not isinstance(manifest, dict):
        raise StableError(
            code=ErrorCode.INTEGRITY_ERROR, message="backup manifest is not an object"
        )
    _verify_manifest(manifest, source_dir)
    if data_dir.exists() and any(data_dir.iterdir()):
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="restore target data directory is not empty",
            details={"data_dir": str(data_dir)},
        )
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_private_path(data_dir)

    staging = data_dir / ".restore-staging"
    staging.mkdir(mode=0o700)
    secure_private_path(staging)
    try:
        for entry in manifest["files"]:
            relpath = str(entry["relpath"])
            target = staging / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            if relpath.startswith("keys/"):
                parent=staging/'keys'
                for part in target.parent.relative_to(parent).parts:
                    secure_private_path(parent)
                    parent=parent/part
                secure_private_path(parent)
            shutil.copy2(source_dir / relpath, target)
            if relpath.startswith("keys/"):
                secure_private_path(target)
        for entry in manifest["files"]:
            relpath = str(entry["relpath"])
            final = data_dir / relpath
            final.parent.mkdir(parents=True, exist_ok=True)
            if relpath.startswith("keys/"):
                parent=data_dir/'keys'
                for part in final.parent.relative_to(parent).parts:
                    secure_private_path(parent)
                    parent=parent/part
                secure_private_path(parent)
            os.replace(staging / relpath, final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    db_path = data_dir / "meta.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="restored meta.db failed integrity_check",
            )
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="restored meta.db failed foreign_key_check",
            )
        verify_store_identity(conn)
        report = run_integrity_doctor(db_path, cas_root=data_dir)
        if not report.ok:
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="restored store failed integrity doctor",
                details={"findings": report.findings[:5]},
            )
        realm_id = str(manifest["realm_id"])
        quarantined = conn.execute(
            "SELECT operation_id FROM operations"
            " WHERE realm_id = ? AND status IN ('ACCEPTED','RUNNING')",
            (realm_id,),
        ).fetchall()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for (operation_id,) in quarantined:
                conn.execute(
                    "UPDATE operations SET status='FAILED_RECOVERY', error_json=?"
                    " WHERE operation_id=? AND status IN ('ACCEPTED','RUNNING')",
                    (b'{"reason_code":"RESTORE_QUARANTINE"}', operation_id),
                )
            fact_id = _append_restore_fact(
                conn,
                realm_id,
                f"operation://{new_uuid7()}",
                event_type="backup_snapshot_restored",
                payload={
                    "manifest_sha256": hashlib.sha256(
                        manifest_path.read_bytes()
                    ).hexdigest(),
                    "source_dir": str(source_dir),
                    "quarantined_operations": len(quarantined),
                },
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return {
            "realm_id": realm_id,
            "epoch_id": str(manifest["epoch_id"]),
            "meta_revision": int(manifest["meta_revision"]),
            "fact_id": fact_id,
            "quarantined_operations": len(quarantined),
            "data_dir": str(data_dir),
        }
    finally:
        conn.close()


# -- upgrade preflight (§41.47.2) ---------------------------------------------------


def preflight_upgrade(conn: sqlite3.Connection, data_dir: Path) -> dict[str, Any]:
    """Manifest-only preflight: identity, migration chain and free space."""

    verify_store_identity(conn)
    data_dir = Path(data_dir).resolve()
    db_bytes = (data_dir / "meta.db").stat().st_size
    cas_bytes = 0
    artifacts_dir = data_dir / "artifacts"
    if artifacts_dir.is_dir():
        for dirpath, _dirnames, filenames in os.walk(artifacts_dir):
            for name in filenames:
                cas_bytes += (Path(dirpath) / name).stat().st_size
    required = int(1.2 * (db_bytes + cas_bytes))
    free = shutil.disk_usage(data_dir).free
    if free < required:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="insufficient free space for upgrade (need >= 1.2x data)",
            details={"required_bytes": required, "free_bytes": free},
        )
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    return {
        "current_schema_version": current,
        "target_schema_version": MIGRATION_VERSION,
        "pending_migrations": max(MIGRATION_VERSION - current, 0),
        "required_free_bytes": required,
        "free_bytes": free,
    }


def run_upgrade(conn: sqlite3.Connection, data_dir: Path) -> dict[str, Any]:
    """Preflight, then apply adjacent migrations in one DB transaction.

    v0.1 ships a single frozen migration, so a current store reports
    ``UP_TO_DATE`` without any write; a store behind the frozen target is
    rejected because no migration path exists in this release.
    """

    preflight = preflight_upgrade(conn, data_dir)
    if preflight["pending_migrations"] == 0:
        return {"status": "UP_TO_DATE", **preflight, "upgraded": False}
    raise StableError(
        code=ErrorCode.FAILED_PRECONDITION,
        message="no migration path from the current schema version",
        details={"current": preflight["current_schema_version"]},
    )
