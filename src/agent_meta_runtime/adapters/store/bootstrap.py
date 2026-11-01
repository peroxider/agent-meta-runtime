"""Core bootstrap transaction (§41.57.1): steps 5–10 in one SQLite txn.

``bootstrap_core`` creates the Realm, Epoch 0, the Root/Service Ed25519
Principals, the Root and Service Grants, the Runtime builtin Artifacts
(§41.57.2 boundary), the ``composition_refs`` revision-0 READY sentinel
and the ``runtime_initialized`` / ``readiness_changed`` Facts — all in a
single transaction, so a crash leaves either an empty store or a complete
one. CAS bytes for the builtin artifacts are staged by the caller before
the transaction; on failure the caller performs best-effort cleanup.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Mapping

from ...domain.authority import (
    Grant,
    GrantConstraints,
    Scope,
    ScopeTarget,
)
from ...domain.canonical import canonical_json
from ...domain.envelope import CommandEnvelope
from ...domain.facts import GENESIS_FACT_HEAD
from ...domain.errors import ErrorCode, StableError
from ...domain.execution_tokens import ExecutionTokenVerifier
from ...domain.ids import new_uuid7
from ..crypto import verify_signature
from ...ports.repositories import FactAppendRequest
from .authority import (
    RootBootstrapRequest,
    _insert_grant,
    _next_meta_revision,
    _write_grant_history,
    bootstrap_root,
)
from .uow import _SqliteStoreTransaction

__all__ = [
    "CoreBootstrapRequest",
    "SERVICE_GRANT_PERMISSIONS",
    "bootstrap_core",
    "builtin_artifact_documents",
]

#: Service Grant holds exactly the reconcile / Task scheduler / fact
#: projection / token issue / Harness lifecycle permissions (§41.57.1 step 8).
SERVICE_GRANT_PERMISSIONS = frozenset(
    {
        "runtime.reconcile",
        "task.execute",
        "runtime.project",
        "runtime.token.issue",
        "harness.install",
        "harness.activate",
        "harness.deactivate",
        "harness.uninstall",
    }
)

_RUNTIME_PUBLIC_API_VERSION = "1.6.0"
_HARNESS_CONTRACT_VERSION = "1.1.0"
_CAPABILITY_CONTRACT_VERSION = "1.0.0"


def builtin_artifact_documents(realm_id: str) -> list[tuple[str, str, str, dict[str, Any]]]:
    """(name, kind, media_type, document) for the §41.57.2 builtin set."""

    permissions = sorted(
        {
            "task.submit", "task.execute", "task.cancel", "task.budget.extend",
            "model.invoke", "artifact.put", "artifact.read.restricted", "artifact.verify",
            "composition.validate", "composition.commit", "composition.promote",
            "composition.rollback", "capability.invoke", "capability.inspect",
            "harness.install", "harness.activate", "harness.deactivate", "harness.uninstall",
            "state.read", "state.write", "state.migrate", "authority.inspect",
            "authority.grant", "authority.delegate", "authority.revoke",
            "experiment.run", "evaluation.record", "runtime.reflect", "runtime.diagnostics",
            "runtime.reconcile", "runtime.project", "runtime.token.issue",
            "runtime.admin.stop", "scratch.create", "scratch.execute", "scratch.inspect",
            "scratch.export", "scratch.release", "operations.backup", "operations.gc",
            "operations.repair", "effect.execute.irreversible",
        }
    )
    return [
        (
            "constitution",
            "policy",
            "application/json",
            {
                "schema": "constitution/v1",
                "realm_id": realm_id,
                "principles": [
                    "explicit-authority",
                    "canonical-ledger",
                    "orthogonal-subsystems",
                    "fail-closed",
                ],
                "version": "1.0.0",
            },
        ),
        (
            "schema_registry",
            "schema",
            "application/json",
            {
                "schema": "meta-schema-registry/v1",
                "entities": [
                    "realm", "epoch", "principal", "grant", "artifact", "composition",
                    "capability", "task", "action", "invocation", "fact", "state",
                    "experiment", "evaluation", "evidence",
                ],
                "version": "1.0.0",
            },
        ),
        (
            "permission_registry",
            "policy",
            "application/json",
            {
                "schema": "permission-registry/v1",
                "permissions": permissions,
                "version": "1.0.0",
            },
        ),
        (
            "redaction_policy",
            "policy",
            "application/json",
            {
                "schema": "redaction-policy/v1",
                "rules": [{"target": "credential", "action": "omit"}],
                "version": "1.0.0",
            },
        ),
        (
            "retention_policy",
            "policy",
            "application/json",
            {
                "schema": "retention-policy/v1",
                "defaults": {"facts": "permanent", "cas_orphans_days": 7},
                "version": "1.0.0",
            },
        ),
        (
            "retry_policy",
            "policy",
            "application/json",
            {
                "schema": "retry-policy/v1",
                "defaults": {"max_attempts": 3, "backoff": "exponential"},
                "version": "1.0.0",
            },
        ),
        (
            "budget_policy",
            "policy",
            "application/json",
            {
                "schema": "budget-policy/v1",
                "defaults": {"max_turns": 100, "max_steps": 10000,
                             "max_model_calls": 10000},
                "version": "1.0.0",
            },
        ),
        (
            "harness_contract",
            "contract",
            "application/json",
            {
                "schema": "harness-contract/v1",
                "public_api_version": _RUNTIME_PUBLIC_API_VERSION,
                "manifest_schema": "harness-package/v1",
                "artifact_format": "AMPAK1",
                "capability_contract_version": _CAPABILITY_CONTRACT_VERSION,
                "version": _HARNESS_CONTRACT_VERSION,
            },
        ),
    ]


@dataclass(frozen=True, slots=True)
class CoreBootstrapRequest:
    """Everything the single bootstrap transaction needs."""

    realm_id: str
    epoch_id: str
    root_principal_id: str
    root_public_key: bytes
    service_principal_id: str
    service_public_key: bytes
    recovery_code_hash: str
    builtin_artifacts: Mapping[str, str]  # name → artifact_id (CAS already staged)
    builtin_storage_paths: Mapping[str, str]
    command_id: str = ""
    root_grant_id: str | None = None
    service_certificate: bytes | None = None
    service_certificate_artifact_id: str | None = None
    service_certificate_storage_path: str | None = None


def bootstrap_core(conn: sqlite3.Connection, request: CoreBootstrapRequest) -> dict[str, Any]:
    """Run §41.57.1 steps 5–10 in exactly one transaction.

    The CAS blobs for ``builtin_artifacts`` must already be staged; this
    function registers the artifact rows. Returns the bootstrap receipt.
    """

    certificate_fields = (request.service_certificate, request.service_certificate_artifact_id, request.service_certificate_storage_path)
    if any(value is not None for value in certificate_fields):
        if not all(value is not None for value in certificate_fields):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="bootstrap Service certificate inputs are incomplete")
        if not isinstance(request.service_certificate_storage_path, str) or not request.service_certificate_storage_path:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="bootstrap Service certificate storage identity is invalid")
        ExecutionTokenVerifier(root_principal_id=request.root_principal_id, root_public_key=request.root_public_key,
            realm_id=request.realm_id, epoch_id=request.epoch_id, certificate=request.service_certificate, verify_signature=verify_signature)
        import json
        payload = json.loads(request.service_certificate)["certificate"]
        if (payload["service_principal_id"] != request.service_principal_id or payload["public_key"] != request.service_public_key.hex()
                or request.service_certificate_artifact_id != "artifact://sha256/" + hashlib.sha256(request.service_certificate).hexdigest()):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="bootstrap Service certificate identity/content differs")
    conn.execute("BEGIN IMMEDIATE")
    try:
        now_us = _store_now(conn)
        transaction_id = "transaction://" + new_uuid7()
        command_id = request.command_id or ("task://" + new_uuid7())
        conn.execute(
            "INSERT INTO realms(realm_id, epoch_id, next_seq, fact_head_hash,"
            " current_meta_revision, created_at_us) VALUES (?, ?, 1, ?, 0, ?)",
            (request.realm_id, request.epoch_id, GENESIS_FACT_HEAD, now_us),
        )
        envelope = CommandEnvelope(
            command_id=command_id,
            realm_id=request.realm_id,
            actor_id=request.root_principal_id,
            authority_grant_id=None,
            expected_meta_revision=None,
            causal_parent_action_id=None,
            payload_type="runtime.init/v1",
            payload_schema_version=1,
            payload={"builtin_artifacts": dict(request.builtin_artifacts)},
            auth_nonce=None,
            auth_issued_at_us=None,
            auth_signature=None,
        )
        txn = _SqliteStoreTransaction(
            conn, envelope, transaction_id=transaction_id, recorded_at_us=now_us
        )

        def fact(entity_type: str, entity_id: str, event_type: str, payload: Mapping[str, Any]) -> str:
            return txn.append_fact(
                FactAppendRequest(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    event_type=event_type,
                    schema_version=1,
                    payload=dict(payload),
                    occurred_at_us=now_us,
                    actor_id=request.root_principal_id,
                )
            )

        # -- step 7: builtin artifacts (rows first: epochs FK references them)
        for name, kind, media_type, document in builtin_artifact_documents(request.realm_id):
            artifact_id = request.builtin_artifacts[name]
            body = canonical_json(document)
            conn.execute(
                "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
                " schema_version, created_by, created_at_us, parents_json,"
                " manifest_json, integrity_status)"
                " VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 'VALID')",
                (
                    artifact_id,
                    kind,
                    media_type,
                    len(body),
                    request.root_principal_id,
                    now_us,
                    canonical_json([]),
                    canonical_json({"builtin": name, "size_bytes": len(body),
                                    "storage_relpath": request.builtin_storage_paths[name]}),
                ),
            )
            fact(
                "artifact", artifact_id, "artifact_registered",
                {"builtin": name, "kind": kind},
            )

        # -- steps 5/6/8a: realm epoch, Root Principal, Root Grant, recovery
        root_receipt = bootstrap_root(
            RootBootstrapRequest(
                realm_id=request.realm_id,
                epoch_id=request.epoch_id,
                principal_id=request.root_principal_id,
                public_key=request.root_public_key,
                recovery_code_hash=request.recovery_code_hash,
                constitution_artifact_id=request.builtin_artifacts["constitution"],
                meta_root_artifact_id=request.builtin_artifacts["schema_registry"],
                ordinal=0,
                grant_id=request.root_grant_id,
            )
        )(txn)

        # -- steps 6/8b: Service Principal + scoped Service Grant
        service_identity = {
            "algorithm": "Ed25519",
            "public_key_hex": request.service_public_key.hex(),
            "key_fingerprint": hashlib.sha256(request.service_public_key).hexdigest(),
        }
        conn.execute(
            "INSERT INTO principals(principal_id, realm_id, kind,"
            " public_identity_json, status, created_at_us)"
            " VALUES (?, ?, 'SERVICE', ?, 'ACTIVE', ?)",
            (
                request.service_principal_id,
                request.realm_id,
                canonical_json(service_identity),
                now_us,
            ),
        )
        grant_id = f"grant://{new_uuid7()}"
        service_grant = Grant(
            grant_id=grant_id,
            epoch_id=request.epoch_id,
            issuer_id=request.root_principal_id,
            subject_id=request.service_principal_id,
            permissions=SERVICE_GRANT_PERMISSIONS,
            scope=Scope(
                realm_id=request.realm_id, targets=(ScopeTarget(type="REALM_ALL"),)
            ),
            constraints=GrantConstraints(),
            delegable=False,
            delegation_depth=1,
            status="ACTIVE",
            issued_at_us=now_us,
        )
        _insert_grant(txn, service_grant)
        service_fact = fact(
            "authority", grant_id, "grant_created",
            {"subject_id": request.service_principal_id, "service": "true"},
        )
        _write_grant_history(
            conn,
            grant_id=grant_id,
            meta_revision=_next_meta_revision(txn),
            status="ACTIVE",
            effective_at_us=now_us,
            source_fact_id=service_fact,
        )

        if request.service_certificate is not None:
            certificate_id = request.service_certificate_artifact_id
            conn.execute("INSERT INTO artifacts(artifact_id,kind,media_type,size_bytes,schema_version,created_by,created_at_us,parents_json,manifest_json,integrity_status) "
                "VALUES (?,'authority_certificate','application/json',?,1,?,?,?,?,'VALID')",
                (certificate_id, len(request.service_certificate), request.root_principal_id, now_us, canonical_json([]),
                 canonical_json({"storage_relpath": request.service_certificate_storage_path, "size_bytes": len(request.service_certificate)})))
            fact("artifact", certificate_id, "artifact_registered", {"kind": "authority_certificate", "service_principal_id": request.service_principal_id})

        # -- step 9: composition_refs revision-0 READY sentinel (no pseudo row)
        conn.execute(
            "INSERT INTO composition_refs(realm_id, desired_revision,"
            " serving_revision, realized_revision, desired_cas, serving_cas,"
            " realized_cas, reconcile_status)"
            " VALUES (?, 0, 0, 0, 0, 0, 0, 'READY')",
            (request.realm_id,),
        )

        # -- step 10: init + readiness facts
        fact(
            "runtime", request.realm_id, "runtime_initialized",
            {
                "realm_id": request.realm_id,
                "epoch_id": request.epoch_id,
                "root_principal_id": request.root_principal_id,
                "service_principal_id": request.service_principal_id,
                "root_grant_id": root_receipt["grant_id"],
                "builtin_artifacts": dict(request.builtin_artifacts),
                **({"service_certificate_artifact_id": request.service_certificate_artifact_id} if request.service_certificate is not None else {}),
            },
        )
        fact(
            "runtime", request.realm_id, "readiness_changed",
            {
                "reason_code": "bootstrap",
                "old_status": "NOT_READY",
                "new_status": "CORE_READY",
                "serving_ready": False,
            },
        )

        first_seq, _last_seq = txn._finalize_chain()
        meta_revision = 1
        conn.execute(
            "UPDATE realms SET current_meta_revision = ? WHERE realm_id = ?",
            (meta_revision, request.realm_id),
        )
        conn.execute(
            "INSERT INTO transactions(transaction_id, realm_id, command_id,"
            " primary_aggregate_type, primary_aggregate_id, status, meta_revision,"
            " committed_at_us) VALUES (?, ?, ?, 'runtime', ?, 'COMMITTED', ?, ?)",
            (transaction_id, request.realm_id, command_id, request.realm_id,
             meta_revision, now_us),
        )
        conn.execute(
            "INSERT INTO meta_revisions(realm_id, revision, transaction_id,"
            " command_id, committed_at_us) VALUES (?, ?, ?, ?, ?)",
            (request.realm_id, meta_revision, transaction_id, command_id, now_us),
        )
        conn.execute(
            "INSERT INTO commands(command_id, realm_id, payload_hash,"
            " authorization_hash, auth_nonce_hash, status, meta_revision,"
            " receipt_json, resource_json, error_json, created_at_us, completed_at_us)"
            " VALUES (?, ?, ?, ?, NULL, 'COMMITTED', ?, ?, NULL, NULL, ?, ?)",
            (
                command_id,
                request.realm_id,
                _payload_hash(envelope),
                _auth_hash(envelope),
                meta_revision,
                canonical_json({"realm_id": request.realm_id, "epoch_id": request.epoch_id}),
                now_us,
                now_us,
            ),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return {
        "realm_id": request.realm_id,
        "epoch_id": request.epoch_id,
        "root_principal_id": request.root_principal_id,
        "root_grant_id": root_receipt["grant_id"],
        "service_principal_id": request.service_principal_id,
        "service_grant_id": grant_id,
        "builtin_artifacts": dict(request.builtin_artifacts),
        "transaction_id": transaction_id,
        "meta_revision": 1,
        "command_id": command_id,
        "first_seq": first_seq,
    }


def _store_now(conn: sqlite3.Connection) -> int:
    return time.time_ns() // 1000


def _payload_hash(envelope: CommandEnvelope) -> str:
    from ...domain.envelope import command_payload_hash

    return command_payload_hash(
        envelope.payload_type, envelope.payload_schema_version, envelope.payload
    )


def _auth_hash(envelope: CommandEnvelope) -> str:
    from ...domain.envelope import command_authorization_hash

    return command_authorization_hash(envelope)
