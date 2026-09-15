"""Managed State use cases: immutable revisions, MVCC ref, cutover (§41.31,
§41.59.3).

``state_revisions`` rows are immutable; the mutable reference lives in
``managed_states`` and moves only through a compare-and-swap on
``(current_revision_id, cas_revision)`` — a stale expectation yields
``REVISION_CONFLICT`` and the old schema is never silently advanced.
Migration binding happens in the serving cutover transaction, which
CAS-checks every planned state and rolls back as a whole on any conflict;
unbound target revisions stay registered but never become current.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_causal_edge, validate_fact_event
from ...domain.ids import new_uuid7
from ...ports.repositories import FactAppendRequest

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = [
    "StateCreateRequest",
    "StateWriteRequest",
    "StateRevisionRegistration",
    "StateMigrationCutoverRequest",
    "create_state",
    "write_state_revision",
    "register_migration_target",
    "migrate_state_cutover",
]


@dataclass(frozen=True, slots=True)
class StateCreateRequest:
    owner_id: str
    schema_id: str
    artifact_id: str
    state_id: str | None = None


@dataclass(frozen=True, slots=True)
class StateWriteRequest:
    state_id: str
    expected_revision_id: str
    expected_cas_revision: int
    schema_id: str
    artifact_id: str
    writer_id: str


@dataclass(frozen=True, slots=True)
class StateRevisionRegistration:
    """An unbound target revision produced by a migration run (§41.59.3)."""

    state_id: str
    source_revision_id: str
    schema_id: str
    artifact_id: str
    state_revision_id: str | None = None


@dataclass(frozen=True, slots=True)
class StateMigrationCutoverRequest:
    """Serving cutover: bind every planned state or roll back entirely."""

    bindings: Sequence[StateRevisionRegistration]
    reason_code: str = "serving_cutover"


def _append_fact(
    txn: "_SqliteStoreTransaction",
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
    payload: dict[str, Any],
    actor_id: str,
) -> str:
    validate_fact_event(entity_type, event_type, 1, payload)
    return txn.append_fact(
        FactAppendRequest(
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            schema_version=1,
            payload=payload,
            occurred_at_us=txn.recorded_at_us,
            actor_id=actor_id,
        )
    )


def _insert_revision(
    txn: "_SqliteStoreTransaction",
    *,
    state_id: str,
    owner_id: str,
    schema_id: str,
    parent_revision_id: str | None,
    artifact_id: str,
    created_by: str,
    state_revision_id: str | None = None,
) -> str:
    revision_id = state_revision_id or f"state-revision://{new_uuid7()}"
    txn._conn.execute(
        "INSERT INTO state_revisions(state_revision_id, state_id, owner_id,"
        " schema_id, parent_revision_id, artifact_id, created_by, created_at_us)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            revision_id,
            state_id,
            owner_id,
            schema_id,
            parent_revision_id,
            artifact_id,
            created_by,
            txn.recorded_at_us,
        ),
    )
    return revision_id


def _state_ref_history(
    txn: "_SqliteStoreTransaction",
    *,
    state_id: str,
    state_revision_id: str,
    source_fact_id: str,
) -> None:
    row = txn._conn.execute(
        "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
        (txn._envelope.realm_id,),
    ).fetchone()
    meta_revision = int(row[0]) + 1
    txn._conn.execute(
        "INSERT INTO state_ref_history(state_id, meta_revision,"
        " state_revision_id, source_fact_id) VALUES (?, ?, ?, ?)",
        (state_id, meta_revision, state_revision_id, source_fact_id),
    )


def create_state(request: StateCreateRequest):
    """Create a Managed State with its initial immutable revision (cas=1)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        state_id = request.state_id or f"state://{new_uuid7()}"
        revision_id = _insert_revision(
            txn,
            state_id=state_id,
            owner_id=request.owner_id,
            schema_id=request.schema_id,
            parent_revision_id=None,
            artifact_id=request.artifact_id,
            created_by=request.owner_id,
        )
        txn._conn.execute(
            "INSERT INTO managed_states(state_id, owner_id, schema_id,"
            " current_revision_id, cas_revision, status, updated_at_us)"
            " VALUES (?, ?, ?, ?, 1, 'ACTIVE', ?)",
            (
                state_id,
                request.owner_id,
                request.schema_id,
                revision_id,
                txn.recorded_at_us,
            ),
        )
        fact_id = _append_fact(
            txn,
            entity_type="state",
            entity_id=state_id,
            event_type="state_revision_created",
            payload={"state_revision_id": revision_id, "initial": "true"},
            actor_id=request.owner_id,
        )
        _state_ref_history(
            txn,
            state_id=state_id,
            state_revision_id=revision_id,
            source_fact_id=fact_id,
        )
        return {
            "state_id": state_id,
            "state_revision_id": revision_id,
            "cas_revision": 1,
        }

    return mutator


def write_state_revision(request: StateWriteRequest):
    """MVCC write: CAS on (current_revision_id, cas_revision) or conflict.

    A concurrent writer that already advanced the ref causes
    ``REVISION_CONFLICT``; the caller must re-read and retry — the runtime
    never auto-overwrites (§41.59.3).
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        row = conn.execute(
            "SELECT owner_id, current_revision_id, cas_revision FROM managed_states"
            " WHERE state_id = ?",
            (request.state_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"state not found: {request.state_id}",
            )
        owner_id, current_revision, cas_revision = row
        if current_revision != request.expected_revision_id:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="state moved since the write was planned",
                details={
                    "state_id": request.state_id,
                    "expected_revision_id": request.expected_revision_id,
                },
            )
        if int(cas_revision) != request.expected_cas_revision:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="state cas_revision mismatch",
                details={
                    "state_id": request.state_id,
                    "expected_cas_revision": str(request.expected_cas_revision),
                },
            )
        revision_id = _insert_revision(
            txn,
            state_id=request.state_id,
            owner_id=owner_id,
            schema_id=request.schema_id,
            parent_revision_id=request.expected_revision_id,
            artifact_id=request.artifact_id,
            created_by=request.writer_id,
        )
        cursor = conn.execute(
            "UPDATE managed_states SET current_revision_id = ?,"
            " cas_revision = cas_revision + 1, updated_at_us = ?"
            " WHERE state_id = ? AND current_revision_id = ? AND cas_revision = ?",
            (
                revision_id,
                txn.recorded_at_us,
                request.state_id,
                request.expected_revision_id,
                request.expected_cas_revision,
            ),
        )
        if cursor.rowcount != 1:  # pragma: no cover - serialized single writer
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="state CAS update lost the race",
            )
        fact_id = _append_fact(
            txn,
            entity_type="state",
            entity_id=request.state_id,
            event_type="state_revision_created",
            payload={"state_revision_id": revision_id, "initial": "false"},
            actor_id=request.writer_id,
        )
        _state_ref_history(
            txn,
            state_id=request.state_id,
            state_revision_id=revision_id,
            source_fact_id=fact_id,
        )
        return {
            "state_id": request.state_id,
            "state_revision_id": revision_id,
            "cas_revision": request.expected_cas_revision + 1,
        }

    return mutator


def register_migration_target(binding: StateRevisionRegistration):
    """Register an unbound migration target revision (no ref movement).

    Survives a failed cutover as an auditable revision row; it can only become
    current through ``migrate_state_cutover`` (§41.59.3).
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        row = conn.execute(
            "SELECT owner_id, current_revision_id FROM managed_states"
            " WHERE state_id = ?",
            (binding.state_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"state not found: {binding.state_id}",
            )
        if row[1] != binding.source_revision_id:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="migration source revision no longer current",
                details={"state_id": binding.state_id},
            )
        revision_id = _insert_revision(
            txn,
            state_id=binding.state_id,
            owner_id=row[0],
            schema_id=binding.schema_id,
            parent_revision_id=binding.source_revision_id,
            artifact_id=binding.artifact_id,
            created_by=txn._envelope.actor_id,
            state_revision_id=binding.state_revision_id,
        )
        fact_id = _append_fact(
            txn,
            entity_type="state",
            entity_id=binding.state_id,
            event_type="state_revision_created",
            payload={"state_revision_id": revision_id, "bound": "false"},
            actor_id=txn._envelope.actor_id,
        )
        validate_causal_edge("supersedes", revision_id, binding.source_revision_id)
        conn.execute(
            "INSERT INTO causal_edges(realm_id, from_id, edge_type, to_id,"
            " source_fact_id) VALUES (?, ?, 'supersedes', ?, ?)",
            (txn._envelope.realm_id, revision_id, binding.source_revision_id, fact_id),
        )
        return {
            "state_id": binding.state_id,
            "state_revision_id": revision_id,
            "bound": False,
        }

    return mutator


def migrate_state_cutover(request: StateMigrationCutoverRequest):
    """Bind all planned target revisions or roll back entirely (§41.59.3).

    Every planned state is CAS-checked against its planned
    ``source_revision_id`` inside one transaction; any conflict raises and the
    whole command rolls back, leaving the unbound targets unbound.
    """

    if not request.bindings:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="cutover requires at least one state binding",
        )
    for binding in request.bindings:
        if not binding.state_revision_id:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="cutover bindings must name a registered target revision",
                details={"state_id": binding.state_id},
            )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        for binding in request.bindings:
            cursor = conn.execute(
                "UPDATE managed_states SET current_revision_id = ?,"
                " cas_revision = cas_revision + 1, updated_at_us = ?"
                " WHERE state_id = ? AND current_revision_id = ?",
                (
                    binding.state_revision_id,
                    txn.recorded_at_us,
                    binding.state_id,
                    binding.source_revision_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StableError(
                    code=ErrorCode.REVISION_CONFLICT,
                    message="cutover source revision changed; transaction rolled back",
                    details={
                        "state_id": binding.state_id,
                        "source_revision_id": binding.source_revision_id,
                    },
                )
        # Only after every CAS succeeded, write history rows and Facts.
        bound: list[dict[str, str]] = []
        for binding in request.bindings:
            fact_id = _append_fact(
                txn,
                entity_type="state",
                entity_id=binding.state_id,
                event_type="migration_completed",
                payload={
                    "reason_code": request.reason_code,
                    "state_revision_id": binding.state_revision_id or "",
                    "source_revision_id": binding.source_revision_id,
                },
                actor_id=txn._envelope.actor_id,
            )
            _state_ref_history(
                txn,
                state_id=binding.state_id,
                state_revision_id=binding.state_revision_id or "",
                source_fact_id=fact_id,
            )
            bound.append(
                {
                    "state_id": binding.state_id,
                    "state_revision_id": binding.state_revision_id or "",
                }
            )
        return {"bound": bound}

    return mutator
