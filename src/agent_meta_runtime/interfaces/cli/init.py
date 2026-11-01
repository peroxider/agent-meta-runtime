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
from ...adapters.credentials import (
    InsecureDevCredentialStore, WindowsCredentialStore, open_key_store, write_store_config,
)
from ...adapters.private_paths import secure_private_path
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


def _feature_summary(profile):
    return {"credential_store": profile, "execution_backends": ["in_memory", "portable"],
            "ipython_scratch": "available" if _ipython_available() else "deferred"}


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


def run_init(data_dir: Path, *, insecure_dev_credential_file: bool = False) -> InitReport:
    """Initialize a data directory or verify an already-initialized one."""

    data_dir = Path(data_dir).resolve()
    db_path = data_dir / "meta.db"
    if db_path.exists():
        with acquire_daemon_lock(data_dir, endpoint="init", instance_id=uuid.uuid4().hex):
            return _reinit(data_dir, db_path, allow_insecure=insecure_dev_credential_file)
    if data_dir.exists() and any(data_dir.iterdir()):
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="data directory is not empty and has no bootstrap database",
            details={"data_dir": str(data_dir)},
        )
    if os.name != "nt" and not insecure_dev_credential_file:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION,
                          message="a supported OS credential store is required; the insecure dev file must be explicitly enabled")
    return _fresh_init(data_dir, db_path, insecure_dev_credential_file=insecure_dev_credential_file)


# -- fresh init ---------------------------------------------------------------


def _fresh_init(data_dir: Path, db_path: Path, *, insecure_dev_credential_file: bool) -> InitReport:
    created: list[Path] = []
    data_dir.mkdir(parents=True, exist_ok=True)
    secure_private_path(data_dir)
    for name in _SECURE_SUBDIRS:
        (data_dir / name).mkdir(mode=0o700, exist_ok=True)
    cas = FilesystemCas(data_dir)
    lock = acquire_daemon_lock(data_dir, endpoint="init", instance_id=uuid.uuid4().hex)
    try:
        conn = initialize_store(db_path)
        created.append(db_path)
        try:
            return _bootstrap_transaction(data_dir, conn, cas, created, insecure_dev_credential_file=insecure_dev_credential_file)
        finally:
            conn.close()
    except BaseException:
        # Never delete keys after an ambiguous SQLite commit outcome. If the
        # DB is unreadable or contains a Root, retain its protected material
        # for explicit recovery rather than risking destruction of Authority.
        committed_or_unknown = True
        try:
            from ...adapters.store.connection import connect_store

            probe = connect_store(db_path)
            try:
                committed_or_unknown = probe.execute("SELECT 1 FROM principals WHERE kind='OPERATOR_ROOT' LIMIT 1").fetchone() is not None
            finally:
                probe.close()
        except Exception:
            pass
        if not committed_or_unknown:
            _cleanup(data_dir, created)
        raise
    finally:
        lock.release()


def _bootstrap_transaction(
    data_dir: Path, conn, cas: FilesystemCas, created: list[Path], *, insecure_dev_credential_file: bool
) -> InitReport:
    keys_dir = data_dir / "keys"
    root_pair = Ed25519KeyPair.generate()
    service_pair = Ed25519KeyPair.generate()
    recovery_code = generate_recovery_code()
    key_handles: dict[str, str] = {}
    root_actor_id = "principal://operator-root/" + new_uuid7()
    root_grant_id = "grant://" + new_uuid7()
    epoch_id = "epoch://" + new_uuid7()
    service_principal_id = "principal://service/" + new_uuid7()
    store = InsecureDevCredentialStore(keys_dir, create=True) if insecure_dev_credential_file else WindowsCredentialStore(keys_dir, create=True)
    for name, pair in (("root", root_pair), ("service", service_pair)):
        material = bytearray(pair.private_bytes_raw())
        try:
            key_handles[name] = store.create(material, purpose=f"{name}.ed25519")
            created.append(store._path(key_handles[name]))
        finally:
            material[:] = b"\x00" * len(material)
    created.append(write_store_config(keys_dir, profile=store.profile, handles=key_handles,
                                      operator={"actor_id": root_actor_id, "authority_grant_id": root_grant_id, "public_key_hex": root_pair.public_bytes_raw().hex()}))

    builtin_artifacts: dict[str, str] = {}
    builtin_storage_paths: dict[str, str] = {}
    for name, _kind, _media_type, document in builtin_artifact_documents(REALM_ID):
        body = canonical_json(document)
        relpath = cas.put(body)
        builtin_storage_paths[name] = relpath
        builtin_artifacts[name] = "artifact://sha256/" + hashlib.sha256(body).hexdigest()
        created.append(cas.absolute_path(relpath))

    from ...domain.execution_tokens import issue_service_certificate
    from ...domain.canonical import now_us
    certificate = issue_service_certificate({"service_principal_id": service_principal_id,
        "public_key": service_pair.public_bytes_raw().hex(), "realm_id": REALM_ID, "epoch_id": epoch_id,
        "permissions": ["capability.invoke", "model.invoke"], "not_after": now_us() + 365 * 86_400_000_000},
        root_principal_id=root_actor_id, signer=root_pair.sign)
    certificate_path = cas.put(certificate)
    certificate_id = "artifact://sha256/" + hashlib.sha256(certificate).hexdigest()
    created.append(cas.absolute_path(certificate_path))
    receipt = bootstrap_core(
        conn,
        CoreBootstrapRequest(
            realm_id=REALM_ID,
            epoch_id=epoch_id,
            root_principal_id=root_actor_id,
            root_grant_id=root_grant_id,
            root_public_key=root_pair.public_bytes_raw(),
            service_principal_id=service_principal_id,
            service_public_key=service_pair.public_bytes_raw(),
            recovery_code_hash=root_recovery_hash(recovery_code),
            builtin_artifacts=builtin_artifacts,
            builtin_storage_paths=builtin_storage_paths,
            service_certificate=certificate,
            service_certificate_artifact_id=certificate_id,
            service_certificate_storage_path=certificate_path,
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
        feature_summary=_feature_summary(store.profile),
        recovery_code=recovery_code,
        details={"key_handles": key_handles, "service_grant_id": receipt["service_grant_id"],
                 "root_principal_id": root_actor_id, "root_grant_id": root_grant_id, "service_certificate_artifact_id": certificate_id},
    )


# -- re-init ------------------------------------------------------------------


def _reinit(data_dir: Path, db_path: Path, *, allow_insecure: bool) -> InitReport:
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
            "SELECT payload_json FROM facts WHERE event_type = 'runtime_initialized' LIMIT 1"
        ).fetchone()
        if initialized is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="runtime_initialized fact missing; bootstrap is incomplete",
                details={"data_dir": str(data_dir)},
            )
        initialization = json.loads(initialized[0])
        identities = {}
        for name in ("root", "service"):
            identity = conn.execute(
                "SELECT public_identity_json FROM principals WHERE principal_id=? AND realm_id=?",
                (initialization[f"{name}_principal_id"], row[0]),
            ).fetchone()
            if identity is None:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="bootstrap signing identity is missing")
            identities[name] = json.loads(identity[0])
        if initialization.get("service_certificate_artifact_id") is not None:
            from ...adapters.store.service_certificates import load_service_execution_trust
            load_service_execution_trust(conn, FilesystemCas(data_dir), realm_id=row[0])
    finally:
        conn.close()
    store, handles = open_key_store(data_dir, allow_insecure=allow_insecure)
    operator = json.loads((data_dir / "keys/store.json").read_bytes())["operator"]
    if (operator["actor_id"] != initialization["root_principal_id"]
            or operator["authority_grant_id"] != initialization["root_grant_id"]
            or operator["public_key_hex"] != identities["root"].get("public_key_hex")):
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="operator metadata differs from the committed bootstrap identity")
    # Existence and decryptability are checked without exposing private bytes.
    for name, handle in handles.items():
        with store.get_for_scoped_use(handle, purpose=f"{name}.ed25519") as value:
            if len(value) != 32:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="signing credential has invalid size")
            public_key = Ed25519KeyPair.from_private_bytes(bytes(value)).public_bytes_raw().hex()
            if identities[name].get("algorithm") != "Ed25519" or identities[name].get("public_key_hex") != public_key:
                raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="signing credential differs from committed public identity")
    _clear_init_orphans(data_dir)
    return InitReport(
        realm_id=row[0],
        epoch_id=row[1],
        data_dir=str(data_dir),
        core_ready=True,
        serving_ready=False,
        builtin_artifacts={},
        feature_summary=_feature_summary(store.profile),
        recovery_code=None,
        reinitialized=True,
        details={"key_handles": handles},
    )


def _clear_init_orphans(data_dir: Path) -> None:
    """Next init after a failed one cleans recorded orphans (§41.57.1)."""

    orphan_path = data_dir / "staging" / "init-orphans.jcs"
    if not orphan_path.exists():
        return
    try:
        orphans = json.loads(orphan_path.read_text())
        for entry in orphans.get("paths", []):
            candidate = Path(entry).resolve()
            if candidate.is_relative_to(data_dir.resolve()) and candidate != data_dir.resolve():
                candidate.unlink(missing_ok=True)
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
