"""Composition revision and desired/serving/realized ref use cases (§41.37,
§41.42.2, §41.59.3).

Composition rows are append-only: each ``(realm_id, revision)`` is committed
once with a ``body_hash`` and never updated. The three references in
``composition_refs`` move only through compare-and-swap on their ``*_cas``
counters — a stale expected counter yields ``REVISION_CONFLICT`` and never
overwrites concurrent progress. Every ref change writes
``composition_ref_history`` bound to the command's meta revision.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_fact_event
from ...domain.ids import new_uuid7, validate_id
from ...ports.repositories import FactAppendRequest

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = [
    "CompositionCreateRequest",
    "SetDesiredRequest",
    "SetServingRequest",
    "SetRealizedRequest",
    "create_composition",
    "set_desired",
    "set_serving",
    "set_realized",
]


@dataclass(frozen=True, slots=True)
class CompositionCreateRequest:
    realm_id: str
    body: Mapping[str, Any]
    created_by: str
    revision: int = 1
    composition_id: str | None = None
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class SetDesiredRequest:
    realm_id: str
    revision: int
    expected_cas: int


@dataclass(frozen=True, slots=True)
class SetServingRequest:
    realm_id: str
    revision: int
    expected_cas: int


@dataclass(frozen=True, slots=True)
class SetRealizedRequest:
    realm_id: str
    revision: int
    expected_cas: int


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
    return int(row[0]) + 1


def _refs_row(txn: "_SqliteStoreTransaction", realm_id: str):
    row = txn._conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " desired_cas, serving_cas, realized_cas, reconcile_status"
        " FROM composition_refs WHERE realm_id = ?",
        (realm_id,),
    ).fetchone()
    return tuple(row) if row is not None else None


def _write_ref_history(txn: "_SqliteStoreTransaction", *, source_fact_id: str) -> None:
    refs = _refs_row(txn, txn._envelope.realm_id)
    assert refs is not None
    desired, serving, realized, _, _, _, reconcile_status = refs
    meta_revision = _next_meta_revision(txn)
    txn._conn.execute(
        "INSERT INTO composition_ref_history(realm_id, meta_revision,"
        " desired_revision, serving_revision, realized_revision,"
        " reconcile_status, source_fact_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            txn._envelope.realm_id,
            meta_revision,
            desired,
            serving,
            realized,
            reconcile_status,
            source_fact_id,
        ),
    )


def create_composition(request: CompositionCreateRequest):
    """Commit one immutable composition revision (§41.42.2)."""

    body = dict(request.body)
    if body.get("schema") != "composition/v1":
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="composition body must declare schema composition/v1",
        )
    if body.get("realm_id") != request.realm_id:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="composition body realm_id must match the command realm",
        )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        composition_id = request.composition_id or f"composition://{new_uuid7()}"
        validate_id(composition_id)
        body_json = canonical_json(body)
        body_hash = sha256_hex(body_json)
        try:
            conn.execute(
                "INSERT INTO compositions(composition_id, realm_id, revision,"
                " parent_id, body_json, body_hash, created_by, created_at_us)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    composition_id,
                    request.realm_id,
                    request.revision,
                    request.parent_id,
                    body_json,
                    body_hash,
                    request.created_by,
                    txn.recorded_at_us,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StableError(
                code=ErrorCode.ALREADY_EXISTS,
                message="composition revision already committed",
                details={"composition_id": composition_id},
            ) from exc
        fact_id = _append_fact(
            txn,
            entity_type="composition",
            entity_id=composition_id,
            event_type="composition_committed",
            payload={"revision": str(request.revision), "body_hash": body_hash},
            actor_id=request.created_by,
        )
        return {
            "composition_id": composition_id,
            "revision": request.revision,
            "body_hash": body_hash,
            "fact_id": fact_id,
        }

    return mutator


def _cas_update(
    txn: "_SqliteStoreTransaction",
    *,
    column: str,
    cas_column: str,
    revision: int,
    expected_cas: int,
    new_status: str,
) -> None:
    conn = txn._conn
    realm_id = txn._envelope.realm_id
    cursor = conn.execute(
        f"INSERT INTO composition_refs(realm_id, {column}, {cas_column},"
        " reconcile_status) VALUES (?, ?, 1, ?)"
        f" ON CONFLICT(realm_id) DO UPDATE SET {column} = excluded.{column},"
        f" {cas_column} = composition_refs.{cas_column} + 1,"
        " reconcile_status = excluded.reconcile_status"
        f" WHERE composition_refs.{cas_column} = ?",
        (realm_id, revision, new_status, expected_cas),
    )
    if cursor.rowcount != 1:
        raise StableError(
            code=ErrorCode.REVISION_CONFLICT,
            message=f"{column} CAS conflict; current progress is not overwritten",
            details={"realm_id": realm_id, "expected_cas": str(expected_cas)},
        )


def set_desired(request: SetDesiredRequest):
    """CAS the desired revision and open a reconcile cycle (§41.38 step C)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        exists = conn.execute(
            "SELECT 1 FROM compositions WHERE realm_id = ? AND revision = ?",
            (request.realm_id, request.revision),
        ).fetchone()
        if exists is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="composition revision not found for realm",
                details={"revision": str(request.revision)},
            )
        _cas_update(
            txn,
            column="desired_revision",
            cas_column="desired_cas",
            revision=request.revision,
            expected_cas=request.expected_cas,
            new_status="PENDING",
        )
        fact_id = _append_fact(
            txn,
            entity_type="composition",
            entity_id="composition://plan",
            event_type="reconcile_started",
            payload={"desired_revision": str(request.revision)},
            actor_id=txn._envelope.actor_id,
        )
        _write_ref_history(txn, source_fact_id=fact_id)
        return {"desired_revision": request.revision, "reconcile_status": "PENDING"}

    return mutator


def set_serving(request: SetServingRequest):
    """CAS serving → revision and record the serving switch (§41.38 step F)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        refs = _refs_row(txn, request.realm_id)
        old_serving = refs[1] if refs else 0
        _cas_update(
            txn,
            column="serving_revision",
            cas_column="serving_cas",
            revision=request.revision,
            expected_cas=request.expected_cas,
            new_status="APPLYING",
        )
        fact_id = _append_fact(
            txn,
            entity_type="composition",
            entity_id="composition://plan",
            event_type="serving_switched",
            payload={
                "reason_code": "cutover",
                "old_status": str(old_serving),
                "new_status": str(request.revision),
            },
            actor_id=txn._envelope.actor_id,
        )
        _write_ref_history(txn, source_fact_id=fact_id)
        return {"serving_revision": request.revision}

    return mutator


def set_realized(request: SetRealizedRequest):
    """CAS realized → serving and close the reconcile cycle (§41.38 step H)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _cas_update(
            txn,
            column="realized_revision",
            cas_column="realized_cas",
            revision=request.revision,
            expected_cas=request.expected_cas,
            new_status="READY",
        )
        fact_id = _append_fact(
            txn,
            entity_type="composition",
            entity_id="composition://plan",
            event_type="realization_completed",
            payload={"realized_revision": str(request.revision)},
            actor_id=txn._envelope.actor_id,
        )
        _write_ref_history(txn, source_fact_id=fact_id)
        return {"realized_revision": request.revision, "reconcile_status": "READY"}

    return mutator
