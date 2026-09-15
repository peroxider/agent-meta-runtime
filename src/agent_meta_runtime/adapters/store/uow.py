"""SQLite Unit of Work and command transaction engine (§41.34.4, §41.8).

One command's idempotency claim, canonical mutation, Facts, outbox items and
meta revision commit in a single ``BEGIN IMMEDIATE`` transaction. Facts are
allocated consecutive seqs from ``realms.next_seq`` and chained with the
§41.35 hash; ``realms.fact_head_hash`` is CAS-updated at the end.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Callable, Mapping, Union

from ...domain import facts as fact_chain
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.deadline import Deadline
from ...domain.envelope import (
    CommandEnvelope,
    JsonValue,
    command_authorization_hash,
    command_payload_hash,
)
from ...domain.errors import ErrorCode, StableError, error_from_json
from ...domain.facts import GENESIS_FACT_HEAD
from ...domain.ids import new_uuid7, validate_stable_name
from ..system_runtime import SystemClock, SystemIdGenerator
from .connection import begin_immediate_with_retry

__all__ = [
    "CommitResult",
    "RejectedResult",
    "bootstrap_realm",
    "execute_command",
]

_ID_GEN = SystemIdGenerator()
_CLOCK = SystemClock()


@dataclass(frozen=True)
class CommitResult:
    command_id: str
    transaction_id: str
    realm_id: str
    meta_revision: int
    first_seq: int
    last_seq: int
    fact_ids: tuple[str, ...]
    receipt: Mapping[str, JsonValue]


@dataclass(frozen=True)
class RejectedResult:
    command_id: str
    meta_revision: int
    error: StableError


def bootstrap_realm(
    conn: sqlite3.Connection, realm_id: str, epoch_id: str, *, now_us: int | None = None
) -> None:
    """Create the realm row with genesis fact head and zero meta revision."""

    validate_stable_name(realm_id.split("://", 1)[-1])
    now_us = _CLOCK.now_us() if now_us is None else now_us
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO realms(realm_id, epoch_id, next_seq, fact_head_hash,"
            " current_meta_revision, created_at_us) VALUES (?, ?, 1, ?, 0, ?)",
            (realm_id, epoch_id, GENESIS_FACT_HEAD, now_us),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


class _SqliteStoreTransaction:
    """Mutation facade passed to the aggregate mutator callback."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        envelope: CommandEnvelope,
        *,
        transaction_id: str,
        recorded_at_us: int,
    ) -> None:
        self._conn = conn
        self._envelope = envelope
        self.transaction_id = transaction_id
        self.recorded_at_us = recorded_at_us
        row = conn.execute(
            "SELECT next_seq, fact_head_hash FROM realms WHERE realm_id = ?",
            (envelope.realm_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"realm not found: {envelope.realm_id}",
            )
        self._next_seq: int = row[0]
        self._prev_fact_hash: str = row[1]
        self._original_head = row[1]
        self.fact_ids: list[str] = []
        self.first_seq: int | None = None

    # -- ports.StoreTransaction -------------------------------------------
    def append_fact(self, request) -> str:  # noqa: ANN001 - ports.FactAppendRequest
        seq = self._next_seq
        self._next_seq += 1
        payload_json = canonical_json(dict(request.payload))
        payload_hash = sha256_hex(payload_json)
        fact_hash = fact_chain.compute_fact_hash(
            self._prev_fact_hash,
            realm_id=self._envelope.realm_id,
            seq=seq,
            occurred_at_us=request.occurred_at_us,
            recorded_at_us=self.recorded_at_us,
            actor_id=request.actor_id,
            action_id=request.action_id,
            transaction_id=self.transaction_id,
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            event_type=request.event_type,
            schema_version=request.schema_version,
            payload_hash=payload_hash,
        )
        fact_id = f"fact://{new_uuid7()}"
        self._conn.execute(
            "INSERT INTO facts(fact_id, realm_id, seq, occurred_at_us, recorded_at_us,"
            " actor_id, action_id, transaction_id, entity_type, entity_id, event_type,"
            " schema_version, payload_json, payload_hash, prev_fact_hash, fact_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fact_id,
                self._envelope.realm_id,
                seq,
                request.occurred_at_us,
                self.recorded_at_us,
                request.actor_id,
                request.action_id,
                self.transaction_id,
                request.entity_type,
                request.entity_id,
                request.event_type,
                request.schema_version,
                payload_json,
                payload_hash,
                self._prev_fact_hash,
                fact_hash,
            ),
        )
        self._prev_fact_hash = fact_hash
        self.fact_ids.append(fact_id)
        if self.first_seq is None:
            self.first_seq = seq
        return fact_id

    def enqueue_outbox(self, request) -> str:  # noqa: ANN001 - ports.OutboxRequest
        outbox_id = f"operation://{new_uuid7()}"
        payload_json = canonical_json(dict(request.payload))
        self._conn.execute(
            "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key, payload_json,"
            " payload_hash, state, available_at_us, attempts, created_at_us)"
            " VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, 0, ?)",
            (
                outbox_id,
                self._envelope.realm_id,
                request.kind,
                request.dedupe_key,
                payload_json,
                sha256_hex(payload_json),
                request.available_at_us,
                self.recorded_at_us,
            ),
        )
        return outbox_id

    def execute(self, sql: str, parameters: tuple = ()) -> None:
        self._conn.execute(sql, parameters)

    # -- internals ---------------------------------------------------------
    def _finalize_chain(self) -> tuple[int, int]:
        if not self.fact_ids:
            return 0, 0
        cursor = self._conn.execute(
            "UPDATE realms SET next_seq = ?, fact_head_hash = ?"
            " WHERE realm_id = ? AND fact_head_hash = ?",
            (
                self._next_seq,
                self._prev_fact_hash,
                self._envelope.realm_id,
                self._original_head,
            ),
        )
        if cursor.rowcount != 1:
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="fact head hash CAS failed",
            )
        assert self.first_seq is not None
        return self.first_seq, self.first_seq + len(self.fact_ids) - 1


def _read_replay(
    conn: sqlite3.Connection, envelope: CommandEnvelope, auth_hash: str
) -> CommitResult | RejectedResult | None:
    row = conn.execute(
        "SELECT status, authorization_hash, meta_revision, receipt_json, error_json"
        " FROM commands WHERE command_id = ?",
        (envelope.command_id,),
    ).fetchone()
    if row is None:
        return None
    status, stored_auth, meta_revision, receipt_json, error_json = row
    if stored_auth != auth_hash:
        raise StableError(
            code=ErrorCode.IDEMPOTENCY_CONFLICT,
            message="command_id was already used with a different authorization",
            details={"command_id": envelope.command_id},
        )
    if status == "COMMITTED":
        txn_row = conn.execute(
            "SELECT transaction_id FROM transactions WHERE command_id = ?",
            (envelope.command_id,),
        ).fetchone()
        transaction_id = txn_row[0] if txn_row else ""
        seqs = (
            conn.execute(
                "SELECT fact_id, seq FROM facts WHERE transaction_id = ? ORDER BY seq",
                (transaction_id,),
            ).fetchall()
            if transaction_id
            else []
        )
        return CommitResult(
            command_id=envelope.command_id,
            transaction_id=transaction_id,
            realm_id=envelope.realm_id,
            meta_revision=meta_revision,
            first_seq=seqs[0][1] if seqs else 0,
            last_seq=seqs[-1][1] if seqs else 0,
            fact_ids=tuple(s[0] for s in seqs),
            receipt=dict(json.loads(receipt_json)) if receipt_json else {},
        )
    return RejectedResult(
        command_id=envelope.command_id,
        meta_revision=meta_revision,
        error=error_from_json(json.loads(error_json)),
    )


def _record_rejection(
    conn: sqlite3.Connection,
    envelope: CommandEnvelope,
    error: StableError,
    *,
    payload_hash: str,
    auth_hash: str,
    now_us: int,
) -> RejectedResult:
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO commands(command_id, realm_id, payload_hash,"
            " authorization_hash, auth_nonce_hash, status, meta_revision,"
            " receipt_json, resource_json, error_json, created_at_us, completed_at_us)"
            " VALUES (?, ?, ?, ?, ?, 'REJECTED', 0, NULL, NULL, ?, ?, ?)",
            (
                envelope.command_id,
                envelope.realm_id,
                payload_hash,
                auth_hash,
                sha256_hex(envelope.auth_nonce.encode("utf-8"))
                if envelope.auth_nonce
                else None,
                canonical_json(error.to_json()),
                now_us,
                now_us,
            ),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return RejectedResult(command_id=envelope.command_id, meta_revision=0, error=error)


def execute_command(
    conn: sqlite3.Connection,
    envelope: CommandEnvelope,
    mutator: Callable[[_SqliteStoreTransaction], Mapping[str, JsonValue]],
    *,
    deadline: Deadline,
    now_us: int | None = None,
) -> Union[CommitResult, RejectedResult]:
    """Run the §41.34.4 command transaction algorithm."""

    payload_hash = command_payload_hash(
        envelope.payload_type, envelope.payload_schema_version, envelope.payload
    )
    auth_hash = command_authorization_hash(envelope)

    begin_immediate_with_retry(conn, deadline)
    try:
        replay = _read_replay(conn, envelope, auth_hash)
        if replay is not None:
            conn.rollback()
            return replay
        created_at_us = _CLOCK.now_us() if now_us is None else now_us
        transaction_id = f"transaction://{new_uuid7()}"
        txn = _SqliteStoreTransaction(
            conn, envelope, transaction_id=transaction_id, recorded_at_us=created_at_us
        )
        try:
            receipt = dict(mutator(txn))
        except StableError as exc:
            conn.rollback()
            return _record_rejection(
                conn,
                envelope,
                exc,
                payload_hash=payload_hash,
                auth_hash=auth_hash,
                now_us=created_at_us,
            )
        first_seq, last_seq = txn._finalize_chain()
        meta_revision_row = conn.execute(
            "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
            (envelope.realm_id,),
        ).fetchone()
        meta_revision = meta_revision_row[0] + 1
        conn.execute(
            "UPDATE realms SET current_meta_revision = ? WHERE realm_id = ?",
            (meta_revision, envelope.realm_id),
        )
        conn.execute(
            "INSERT INTO transactions(transaction_id, realm_id, command_id,"
            " primary_aggregate_type, primary_aggregate_id, status, meta_revision,"
            " committed_at_us) VALUES (?, ?, ?, ?, ?, 'COMMITTED', ?, ?)",
            (
                transaction_id,
                envelope.realm_id,
                envelope.command_id,
                envelope.payload_type.split("/", 1)[0].split(".", 1)[0],
                envelope.realm_id,
                meta_revision,
                created_at_us,
            ),
        )
        conn.execute(
            "INSERT INTO meta_revisions(realm_id, revision, transaction_id, command_id,"
            " committed_at_us) VALUES (?, ?, ?, ?, ?)",
            (
                envelope.realm_id,
                meta_revision,
                transaction_id,
                envelope.command_id,
                created_at_us,
            ),
        )
        conn.execute(
            "INSERT INTO commands(command_id, realm_id, payload_hash,"
            " authorization_hash, auth_nonce_hash, status, meta_revision,"
            " receipt_json, resource_json, error_json, created_at_us, completed_at_us)"
            " VALUES (?, ?, ?, ?, ?, 'COMMITTED', ?, ?, NULL, NULL, ?, ?)",
            (
                envelope.command_id,
                envelope.realm_id,
                payload_hash,
                auth_hash,
                sha256_hex(envelope.auth_nonce.encode("utf-8"))
                if envelope.auth_nonce
                else None,
                meta_revision,
                canonical_json(receipt),
                created_at_us,
                created_at_us,
            ),
        )
        conn.commit()
        return CommitResult(
            command_id=envelope.command_id,
            transaction_id=transaction_id,
            realm_id=envelope.realm_id,
            meta_revision=meta_revision,
            first_seq=first_seq,
            last_seq=last_seq,
            fact_ids=tuple(txn.fact_ids),
            receipt=receipt,
        )
    except BaseException:
        conn.rollback()
        raise
