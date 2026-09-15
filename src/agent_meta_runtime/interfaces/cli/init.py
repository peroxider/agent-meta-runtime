"""``agent-meta init`` orchestration (§41.57.1).

Only an absent or empty data directory may be initialized. The
orchestrator performs steps 1–4 and 11 (secure directories, daemon lock,
capability checks, CAS staging of builtin artifact bytes, output); the
§41.57.1 steps 5–10 run inside :func:`bootstrap_core` as one transaction.
Re-init on a complete data directory verifies bootstrap integrity, clears
recorded init orphans and returns the existing Realm — no new keys,
grants or recovery codes. Partial state fails closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...adapters.cas import FilesystemCas
from ...adapters.crypto import (
    Ed25519KeyPair,
    generate_recovery_code,
    root_recovery_hash,
)
from ...adapters.daemon_lock import acquire_daemon_lock
from ...adapters.store import initialize_store
from ...adapters.store.bootstrap import (
    CoreBootstrapRequest,
    bootstrap_core,
    builtin_artifact_documents,
)
from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7

__all__ = ["InitReport", "REALM_ID", "run_init"]

REALM_ID = "realm://main"

_SECURE_SUBDIRS = ("run", "keys", "workspace", "diagnostics", "backups")


def _ipython_available() -> bool:
    try:
        import ipykernel  # noqa: F401
    except ImportError:
        return False
    return True


_FEATURE_SUMMARY = {
    "credential_store": "INSECURE_TEST_ONLY",
    "execution_backends": ["in_memory", "portable"],
    "ipython_scratch": "available" if _ipython_available() else "deferred",
}


@dataclass(frozen=True, slots=True)
class InitReport:
    realm_id: str
    epoch_id: str
    data_dir: str
    core_ready: bool
    serving_ready: bool
    builtin_artifacts: dict[str, str]
    feature_summary: dict[str, Any]
    recovery_code: str | None = None  # shown exactly once, never persisted
    reinitialized: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def run_init(data_dir: Path) -> InitReport:
    """Initialize a data directory or verify an already-initialized one."""

    data_dir = Path(data_dir).resolve()
    db_path = data_dir / "meta.db"
    if db_path.exists():
        return _reinit(data_dir, db_path)
    if data_dir.exists() and any(data_dir.iterdir()):
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="data directory is not empty and has no bootstrap database",
            details={"data_dir": str(data_dir)},
        )
    return _fresh_init(data_dir, db_path)


# -- fresh init ---------------------------------------------------------------


def _fresh_init(data_dir: Path, db_path: Path) -> InitReport:
    created: list[Path] = []
    data_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir, 0o700)
    for name in _SECURE_SUBDIRS:
        (data_dir / name).mkdir(mode=0o700, exist_ok=True)
    cas = FilesystemCas(data_dir)
    lock = acquire_daemon_lock(data_dir, endpoint="init", instance_id=uuid.uuid4().hex)
    try:
        conn = initialize_store(db_path)
        created.append(db_path)
        try:
            return _bootstrap_transaction(data_dir, conn, cas, created)
        finally:
            conn.close()
    except BaseException:
        _cleanup(data_dir, created)
        raise
    finally:
        lock.release()


def _bootstrap_transaction(
    data_dir: Path, conn, cas: FilesystemCas, created: list[Path]
) -> InitReport:
    keys_dir = data_dir / "keys"
    root_pair = Ed25519KeyPair.generate()
    service_pair = Ed25519KeyPair.generate()
    recovery_code = generate_recovery_code()
    key_handles: dict[str, str] = {}
    for name, pair in (("root", root_pair), ("service", service_pair)):
        key_path = keys_dir / f"{name}.key"
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pair.private_bytes_raw())
        created.append(key_path)
        key_handles[name] = "credential://local-keyfile/{}/{}".format(
            hashlib.sha256(str(key_path).encode()).hexdigest()[:16], uuid.uuid4()
        )

    builtin_artifacts: dict[str, str] = {}
    for name, _kind, _media_type, document in builtin_artifact_documents(REALM_ID):
        body = canonical_json(document)
        relpath = cas.put(body)
        builtin_artifacts[name] = "artifact://sha256/" + hashlib.sha256(body).hexdigest()
        created.append(cas.absolute_path(relpath))

    receipt = bootstrap_core(
        conn,
        CoreBootstrapRequest(
            realm_id=REALM_ID,
            epoch_id="epoch://" + new_uuid7(),
            root_principal_id="principal://operator-root/" + new_uuid7(),
            root_public_key=root_pair.public_bytes_raw(),
            service_principal_id="principal://service/" + new_uuid7(),
            service_public_key=service_pair.public_bytes_raw(),
            recovery_code_hash=root_recovery_hash(recovery_code),
            builtin_artifacts=builtin_artifacts,
        ),
    )
    created.clear()  # committed: the rollback candidates are now live state
    return InitReport(
        realm_id=receipt["realm_id"],
        epoch_id=receipt["epoch_id"],
        data_dir=str(data_dir),
        core_ready=True,
        serving_ready=False,
        builtin_artifacts=builtin_artifacts,
        feature_summary=_FEATURE_SUMMARY,
        recovery_code=recovery_code,
        details={"key_handles": key_handles, "service_grant_id": receipt["service_grant_id"]},
    )


# -- re-init ------------------------------------------------------------------


def _reinit(data_dir: Path, db_path: Path) -> InitReport:
    from ...adapters.store.connection import connect_store
    from ...adapters.store.initializer import verify_store_identity

    conn = connect_store(db_path)
    try:
        verify_store_identity(conn)  # schema present; never re-apply DDL here
        row = conn.execute("SELECT realm_id, epoch_id FROM realms").fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="bootstrap transaction incomplete; restore from backup or remove"
                        " the data directory (fail closed)",
                details={"data_dir": str(data_dir)},
            )
        initialized = conn.execute(
            "SELECT 1 FROM facts WHERE event_type = 'runtime_initialized' LIMIT 1"
        ).fetchone()
        if initialized is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="runtime_initialized fact missing; bootstrap is incomplete",
                details={"data_dir": str(data_dir)},
            )
    finally:
        conn.close()
    _clear_init_orphans(data_dir)
    return InitReport(
        realm_id=row[0],
        epoch_id=row[1],
        data_dir=str(data_dir),
        core_ready=True,
        serving_ready=False,
        builtin_artifacts={},
        feature_summary=_FEATURE_SUMMARY,
        recovery_code=None,
        reinitialized=True,
    )


def _clear_init_orphans(data_dir: Path) -> None:
    """Next init after a failed one cleans recorded orphans (§41.57.1)."""

    orphan_path = data_dir / "staging" / "init-orphans.jcs"
    if not orphan_path.exists():
        return
    try:
        orphans = json.loads(orphan_path.read_text())
        for entry in orphans.get("paths", []):
            Path(entry).unlink(missing_ok=True)
        orphan_path.unlink()
    except (OSError, ValueError):
        pass  # recorded orphans are re-reported on the next failed cleanup


# -- failure cleanup ----------------------------------------------------------


def _cleanup(data_dir: Path, created: list[Path]) -> None:
    """Best-effort removal of unreferenced items (§41.57.1 step 10)."""

    orphans: list[str] = []
    for path in created:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            orphans.append(str(path))
    if orphans:
        staging = data_dir / "staging"
        try:
            staging.mkdir(mode=0o700, exist_ok=True)
            staging.joinpath("init-orphans.jcs").write_text(
                json.dumps({"paths": orphans}, sort_keys=True)
            )
        except OSError:
            pass
