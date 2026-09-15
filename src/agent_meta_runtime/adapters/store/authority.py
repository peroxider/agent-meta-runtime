"""Authority store use cases: Root bootstrap, grants, use counters (§41.28).

All mutations run as command mutators inside the caller's ``BEGIN IMMEDIATE``
transaction: authority checks and the ``authority_uses`` reservation commit in
the same transaction as the Action/Effect, the ``UNIQUE(grant_id, action_id,
use_kind)`` key prevents double-charge, and every revoke/expire writes
``authority_grant_history`` plus a Fact. Grant definition columns are protected
by the ``GRANT_DEFINITION_IMMUTABLE`` trigger; only ``status`` may change.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.authority import (
    PERMISSIONS,
    Grant,
    GrantConstraints,
    Scope,
    ScopeTarget,
    authorize,
    validate_delegation,
)
from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_fact_event
from ...domain.facts import GENESIS_FACT_HEAD
from ...domain.ids import new_uuid7
from ...ports.repositories import FactAppendRequest

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = [
    "ROOT_DELEGATION_DEPTH",
    "RootBootstrapRequest",
    "CreateGrantRequest",
    "RevokeGrantRequest",
    "ReserveAuthorityUseRequest",
    "bootstrap_root",
    "create_grant",
    "revoke_grant",
    "reserve_authority_use",
    "load_grant_row",
]

ROOT_DELEGATION_DEPTH = 4

_GRANT_COLUMNS = (
    "grant_id, epoch_id, issuer_id, subject_id, parent_grant_id, permissions_json,"
    " scope_json, constraints_json, delegable, delegation_depth, status,"
    " issued_at_us, expires_at_us, revoked_at_us"
)


@dataclass(frozen=True, slots=True)
class RootBootstrapRequest:
    """``init`` payload: Realm/Epoch 0/Root Principal/Root Grant (§41.28)."""

    realm_id: str
    epoch_id: str
    principal_id: str
    public_key: bytes
    recovery_code_hash: str
    constitution_artifact_id: str = ""
    meta_root_artifact_id: str = ""
    ordinal: int = 0


@dataclass(frozen=True, slots=True)
class CreateGrantRequest:
    """Delegation request: the child grant must not expand any dimension."""

    issuer_grant_id: str
    subject_id: str
    permissions: frozenset[str]
    scope: Scope
    constraints: GrantConstraints = field(default_factory=GrantConstraints)
    delegable: bool = True
    grant_id: str | None = None


@dataclass(frozen=True, slots=True)
class RevokeGrantRequest:
    grant_id: str
    reason_code: str = "operator_revoke"


@dataclass(frozen=True, slots=True)
class ReserveAuthorityUseRequest:
    """Authority check + atomic use reservation for one Action (§41.28)."""

    grant_id: str
    actor_id: str
    permission: str
    action_id: str
    use_kind: str = "execute"
    amount: Mapping[str, int] = field(default_factory=dict)
    resource_target: ScopeTarget | None = None


def _append_fact(
    txn: "_SqliteStoreTransaction",
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    actor_id: str,
) -> str:
    validate_fact_event(entity_type, event_type, 1, dict(payload))
    return txn.append_fact(
        FactAppendRequest(
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            schema_version=1,
            payload=dict(payload),
            occurred_at_us=txn.recorded_at_us,
            actor_id=actor_id,
        )
    )


def _next_meta_revision(txn: "_SqliteStoreTransaction") -> int:
    row = txn._conn.execute(
        "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
        (txn._envelope.realm_id,),
    ).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="realm not found")
    return int(row[0]) + 1


def _write_grant_history(
    conn,
    *,
    grant_id: str,
    meta_revision: int,
    status: str,
    effective_at_us: int,
    source_fact_id: str,
) -> None:
    conn.execute(
        "INSERT INTO authority_grant_history(grant_id, meta_revision, status,"
        " effective_at_us, source_fact_id) VALUES (?, ?, ?, ?, ?)",
        (grant_id, meta_revision, status, effective_at_us, source_fact_id),
    )


def _grant_from_row(row: tuple) -> Grant:
    (
        grant_id,
        epoch_id,
        issuer_id,
        subject_id,
        parent_grant_id,
        permissions_json,
        scope_json,
        constraints_json,
        delegable,
        delegation_depth,
        status,
        issued_at_us,
        expires_at_us,
        revoked_at_us,
    ) = row
    return Grant(
        grant_id=grant_id,
        epoch_id=epoch_id,
        issuer_id=issuer_id,
        subject_id=subject_id,
        permissions=frozenset(json.loads(bytes(permissions_json).decode("utf-8"))),
        scope=Scope.from_json(json.loads(bytes(scope_json).decode("utf-8"))),
        constraints=GrantConstraints.from_json(
            json.loads(bytes(constraints_json).decode("utf-8"))
        ),
        delegable=bool(delegable),
        delegation_depth=int(delegation_depth),
        status=status,
        issued_at_us=int(issued_at_us),
        expires_at_us=expires_at_us,
        revoked_at_us=revoked_at_us,
        parent_grant_id=parent_grant_id,
    )


def load_grant_row(conn, grant_id: str) -> Grant | None:
    """Read-side grant loader (no lazy-expiry side effects)."""

    row = conn.execute(
        f"SELECT {_GRANT_COLUMNS} FROM authority_grants WHERE grant_id = ?",
        (grant_id,),
    ).fetchone()
    return _grant_from_row(row) if row is not None else None


def _load_grant(
    txn: "_SqliteStoreTransaction", grant_id: str, *, now_us: int, actor_id: str
) -> Grant:
    """Load a grant for an authority check. Expiry is evaluated lazily at
    ``authorize`` time from the caller's clock — a denial rolls the whole
    command transaction back, so an EXPIRED status flip can never be durable
    inside the rejecting transaction itself."""

    grant = load_grant_row(txn._conn, grant_id)
    if grant is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND, message=f"grant not found: {grant_id}"
        )
    return grant


def _insert_grant(txn: "_SqliteStoreTransaction", grant: Grant) -> None:
    txn._conn.execute(
        "INSERT INTO authority_grants(grant_id, epoch_id, issuer_id, subject_id,"
        " parent_grant_id, permissions_json, scope_json, constraints_json,"
        " delegable, delegation_depth, status, issued_at_us, expires_at_us,"
        " revoked_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            grant.grant_id,
            grant.epoch_id,
            grant.issuer_id,
            grant.subject_id,
            grant.parent_grant_id,
            canonical_json(sorted(grant.permissions)),
            grant.scope.canonical_bytes(),
            canonical_json(grant.constraints.to_json()),
            int(grant.delegable),
            grant.delegation_depth,
            grant.status,
            grant.issued_at_us,
            grant.expires_at_us,
            grant.revoked_at_us,
        ),
    )


def bootstrap_root(request: RootBootstrapRequest):
    """Create Epoch 0, the Root Principal, the Root Grant and the recovery
    record in one command transaction. A repeated ``init`` fails: the epoch
    unique index and principal primary key admit exactly one Root (§41.28)."""

    public_key = request.public_key
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="Root public key must be 32 raw Ed25519 bytes",
        )
    if not request.recovery_code_hash:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="recovery_code_hash is required; raw codes are never stored",
        )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        now_us = txn.recorded_at_us
        actor_id = txn._envelope.actor_id
        existing = conn.execute(
            "SELECT 1 FROM principals WHERE principal_id = ?",
            (request.principal_id,),
        ).fetchone()
        if existing is not None:
            raise StableError(
                code=ErrorCode.ALREADY_EXISTS,
                message="Root Principal already exists; init is not repeatable",
                details={"principal_id": request.principal_id},
            )
        conn.execute(
            "INSERT INTO epochs(epoch_id, realm_id, ordinal,"
            " constitution_artifact_id, meta_root_artifact_id,"
            " authority_root_principal_id, fact_root_hash, status, created_at_us)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)",
            (
                request.epoch_id,
                request.realm_id,
                request.ordinal,
                request.constitution_artifact_id,
                request.meta_root_artifact_id,
                request.principal_id,
                GENESIS_FACT_HEAD,
                now_us,
            ),
        )
        identity = {
            "algorithm": "Ed25519",
            "public_key_hex": public_key.hex(),
            "key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        }
        conn.execute(
            "INSERT INTO principals(principal_id, realm_id, kind,"
            " public_identity_json, status, created_at_us)"
            " VALUES (?, ?, 'OPERATOR_ROOT', ?, 'ACTIVE', ?)",
            (
                request.principal_id,
                request.realm_id,
                canonical_json(identity),
                now_us,
            ),
        )
        grant_id = f"grant://{new_uuid7()}"
        grant = Grant(
            grant_id=grant_id,
            epoch_id=request.epoch_id,
            issuer_id=request.principal_id,
            subject_id=request.principal_id,
            permissions=frozenset(PERMISSIONS),
            scope=Scope(realm_id=request.realm_id, targets=(ScopeTarget(type="REALM_ALL"),)),
            constraints=GrantConstraints(unbounded=True),
            delegable=True,
            delegation_depth=ROOT_DELEGATION_DEPTH,
            status="ACTIVE",
            issued_at_us=now_us,
        )
        _insert_grant(txn, grant)
        _append_fact(
            txn,
            entity_type="runtime",
            entity_id=request.epoch_id,
            event_type="epoch_created",
            payload={"epoch_id": request.epoch_id, "ordinal": str(request.ordinal)},
            actor_id=actor_id,
        )
        meta_revision = _next_meta_revision(txn)
        grant_fact = _append_fact(
            txn,
            entity_type="authority",
            entity_id=grant_id,
            event_type="grant_created",
            payload={"subject_id": request.principal_id, "root": "true"},
            actor_id=actor_id,
        )
        _write_grant_history(
            conn,
            grant_id=grant_id,
            meta_revision=meta_revision,
            status="ACTIVE",
            effective_at_us=now_us,
            source_fact_id=grant_fact,
        )
        conn.execute(
            "INSERT INTO root_recovery(realm_id, active_recovery_hash, generation,"
            " created_at_us) VALUES (?, ?, 1, ?)",
            (request.realm_id, request.recovery_code_hash, now_us),
        )
        return {
            "grant_id": grant_id,
            "epoch_id": request.epoch_id,
            "principal_id": request.principal_id,
            "recovery_generation": 1,
        }

    return mutator


def create_grant(request: CreateGrantRequest):
    """Delegate a child grant from an existing ACTIVE parent grant.

    Every dimension is checked for containment; the delegation itself consumes
    one parent use through the atomic counter (§41.28). Unknown permissions
    fail closed inside ``validate_delegation``.
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        now_us = txn.recorded_at_us
        issuer_id = txn._envelope.actor_id
        parent = _load_grant(
            txn, request.issuer_grant_id, now_us=now_us, actor_id=issuer_id
        )
        if parent.subject_id != issuer_id:
            raise StableError(
                code=ErrorCode.AUTHORITY_DENIED,
                message="only the parent grant subject may delegate",
                details={"parent_grant_id": parent.grant_id},
            )
        if "authority.delegate" not in parent.permissions:
            raise StableError(
                code=ErrorCode.AUTHORITY_DENIED,
                message="parent grant lacks authority.delegate",
                details={"parent_grant_id": parent.grant_id},
            )
        child_depth = validate_delegation(
            parent,
            child_permissions=request.permissions,
            child_scope=request.scope,
            child_constraints=request.constraints,
            child_delegable=request.delegable,
        )
        # Delegation consumes one parent use under the command's action key.
        uses_count = conn.execute(
            "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?",
            (parent.grant_id,),
        ).fetchone()[0]
        max_uses = parent.constraints.max_uses
        if max_uses is not None and uses_count >= max_uses:
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message="parent grant use counter exhausted",
                details={"parent_grant_id": parent.grant_id},
            )
        action_key = f"command://{txn._envelope.command_id.split('://', 1)[-1]}"
        if not _reserve_use_row(txn, parent.grant_id, action_key, "delegate", {}):
            raise StableError(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message="parent grant use counter exhausted",
                details={"parent_grant_id": parent.grant_id},
            )
        grant_id = request.grant_id or f"grant://{new_uuid7()}"
        child = Grant(
            grant_id=grant_id,
            epoch_id=parent.epoch_id,
            issuer_id=parent.subject_id,
            subject_id=request.subject_id,
            permissions=request.permissions,
            scope=request.scope,
            constraints=request.constraints,
            delegable=request.delegable,
            delegation_depth=child_depth,
            status="ACTIVE",
            issued_at_us=now_us,
            parent_grant_id=parent.grant_id,
        )
        _insert_grant(txn, child)
        meta_revision = _next_meta_revision(txn)
        fact_id = _append_fact(
            txn,
            entity_type="authority",
            entity_id=grant_id,
            event_type="grant_delegated",
            payload={
                "parent_grant_id": parent.grant_id,
                "subject_id": request.subject_id,
            },
            actor_id=issuer_id,
        )
        _write_grant_history(
            conn,
            grant_id=grant_id,
            meta_revision=meta_revision,
            status="ACTIVE",
            effective_at_us=now_us,
            source_fact_id=fact_id,
        )
        return {
            "grant_id": grant_id,
            "parent_grant_id": parent.grant_id,
            "delegation_depth": child_depth,
        }

    return mutator


def revoke_grant(request: RevokeGrantRequest):
    """Revoke a grant: CAS the status reference and write history + Fact.

    The change is visible to every later authority check in the same or any
    subsequent transaction — there is no grace period (§41.28).
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        now_us = txn.recorded_at_us
        actor_id = txn._envelope.actor_id
        row = conn.execute(
            "SELECT status FROM authority_grants WHERE grant_id = ?",
            (request.grant_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"grant not found: {request.grant_id}",
            )
        if row[0] != "ACTIVE":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="grant is not ACTIVE",
                details={"status": row[0]},
            )
        meta_revision = _next_meta_revision(txn)
        fact_id = _append_fact(
            txn,
            entity_type="authority",
            entity_id=request.grant_id,
            event_type="grant_revoked",
            payload={
                "reason_code": request.reason_code,
                "old_status": "ACTIVE",
                "new_status": "REVOKED",
            },
            actor_id=actor_id,
        )
        cursor = conn.execute(
            "UPDATE authority_grants SET status = 'REVOKED', revoked_at_us = ?"
            " WHERE grant_id = ? AND status = 'ACTIVE'",
            (now_us, request.grant_id),
        )
        if cursor.rowcount != 1:  # pragma: no cover - serialized single writer
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="grant status changed concurrently",
            )
        _write_grant_history(
            conn,
            grant_id=request.grant_id,
            meta_revision=meta_revision,
            status="REVOKED",
            effective_at_us=now_us,
            source_fact_id=fact_id,
        )
        return {"grant_id": request.grant_id, "status": "REVOKED"}

    return mutator


def _reserve_use_row(
    txn: "_SqliteStoreTransaction",
    grant_id: str,
    action_id: str,
    use_kind: str,
    amount: Mapping[str, int],
) -> bool:
    """Insert the use row under the UNIQUE(grant, action, kind) key.

    Returns True for a fresh reservation, False when an identical row already
    exists (idempotent replay). A different amount for the same key is an
    ``IDEMPOTENCY_CONFLICT``.
    """

    conn = txn._conn
    amount_json = canonical_json(dict(amount))
    existing = conn.execute(
        "SELECT amount_json FROM authority_uses WHERE grant_id = ? AND action_id = ?"
        " AND use_kind = ?",
        (grant_id, action_id, use_kind),
    ).fetchone()
    if existing is not None:
        if bytes(existing[0]) != amount_json:
            raise StableError(
                code=ErrorCode.IDEMPOTENCY_CONFLICT,
                message="use already reserved with a different amount",
                details={"grant_id": grant_id, "use_kind": use_kind},
            )
        return False
    conn.execute(
        "INSERT INTO authority_uses(grant_id, action_id, use_kind, amount_json,"
        " meta_revision, used_at_us) VALUES (?, ?, ?, ?, ?, ?)",
        (
            grant_id,
            action_id,
            use_kind,
            amount_json,
            _next_meta_revision(txn),
            txn.recorded_at_us,
        ),
    )
    return True


def reserve_authority_use(request: ReserveAuthorityUseRequest):
    """Run the full authorization order and reserve one use atomically.

    Denials append an ``authority_denied`` Fact and raise ``AUTHORITY_DENIED``;
    the reservation lands in ``authority_uses`` in the same transaction as the
    Action/Effect it authorizes (§41.28).
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        now_us = txn.recorded_at_us
        conn = txn._conn
        grant = _load_grant(
            txn, request.grant_id, now_us=now_us, actor_id=request.actor_id
        )
        # Replay check first: an identical use row returns the original
        # outcome without double-charging — even on a grant that is exhausted
        # or revoked by now.
        existing = conn.execute(
            "SELECT amount_json FROM authority_uses WHERE grant_id = ?"
            " AND action_id = ? AND use_kind = ?",
            (request.grant_id, request.action_id, request.use_kind),
        ).fetchone()
        uses_count = conn.execute(
            "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?",
            (request.grant_id,),
        ).fetchone()[0]
        if existing is not None:
            if bytes(existing[0]) != canonical_json(dict(request.amount)):
                raise StableError(
                    code=ErrorCode.IDEMPOTENCY_CONFLICT,
                    message="use already reserved with a different amount",
                    details={"grant_id": request.grant_id},
                )
            return {"grant_id": request.grant_id, "uses_count": uses_count}
        reason = authorize(
            grant,
            subject_id=request.actor_id,
            permission=request.permission,
            resource_realm=txn._envelope.realm_id,
            resource_target=request.resource_target,
            epoch_id=grant.epoch_id,
            now_us=now_us,
            uses_count=uses_count,
        )
        if reason is not None:
            _append_fact(
                txn,
                entity_type="authority",
                entity_id=request.grant_id,
                event_type="authority_denied",
                payload={
                    "reason_code": reason,
                    "permission": request.permission,
                    "action_id": request.action_id,
                },
                actor_id=request.actor_id,
            )
            raise StableError(
                code=ErrorCode.AUTHORITY_DENIED,
                message=f"authority check failed: {reason}",
                details={
                    "grant_id": request.grant_id,
                    "reason": reason,
                    "permission": request.permission,
                },
            )
        _reserve_use_row(
            txn, request.grant_id, request.action_id, request.use_kind, request.amount
        )
        return {"grant_id": request.grant_id, "uses_count": uses_count + 1}

    return mutator
