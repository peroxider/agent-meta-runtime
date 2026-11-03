"""Transactional outbox dispatcher (§41.38, §41.59.4).

Lease ownership: the daemon holds the unique lock and runs with a fresh
random ``instance_id``; the first recovery transaction resets every
``LEASED`` row owned by another instance back to ``PENDING`` (the lock has
already proven the old owner lost its commit right). Claiming a batch, and
every delivery terminal commit, are short ``BEGIN IMMEDIATE`` transactions;
the external handler call happens strictly outside any store transaction.
Terminal commit is a CAS on ``state='LEASED' AND lease_owner=current`` — a
late owner can never mark a row delivered. Retry ladder 1/2/4/8/16s; more
than 20 attempts or 24h in flight → ``DEAD_LETTER``. Lease deadlines inside
this process are monotonic; wall microseconds are persisted only for
cross-process takeover. When the clock monitor is unstable no new leases are
acquired; held leases may still complete or be abandoned to PENDING within
their monotonic deadline.
"""

from __future__ import annotations

import json
import asyncio
import secrets
import time
from typing import Any, Callable

from ..domain.clock import ClockStabilityMonitor
from ..domain.outbox import (
    DEAD_LETTER_AGE_US,
    MAX_OUTBOX_ATTEMPTS,
    outbox_backoff_s,
)
from ..domain.errors import ErrorCode, StableError
from .steps import Call, drive, drive_async

__all__ = ["OutboxDispatcher", "DeliveryError"]

Handler = Callable[[dict[str, Any]], None]
"""handler(item) performs the external call; raises to schedule a retry."""


class DeliveryError(Exception):
    """Handler failure wrapper preserving the error detail for the outbox."""


class _MissingHandler(DeliveryError):
    pass


class OutboxDispatcher:
    """Lease-based at-least-once dispatcher with stable dedupe upstream."""

    def __init__(
        self,
        conn: Any,
        *,
        handlers: dict[str, Handler],
        instance_id: str | None = None,
        lease_seconds: float = 30.0,
        renewal_interval_s: float = 10.0,
        max_attempts: int = MAX_OUTBOX_ATTEMPTS,
        dead_letter_age_us: int = DEAD_LETTER_AGE_US,
        clock: ClockStabilityMonitor | None = None,
        monotonic: Callable[[], float] | None = None,
        wall: Callable[[], float] | None = None,
        batch_size: int = 16,
    ) -> None:
        self._conn = conn
        self._handlers = handlers
        self._instance_id = instance_id or secrets.token_hex(16)
        self._lease_seconds = lease_seconds
        self._renewal_interval_s = renewal_interval_s
        self._max_attempts = max_attempts
        self._dead_letter_age_us = dead_letter_age_us
        self._clock = clock or ClockStabilityMonitor(monotonic=monotonic, wall=wall)
        self._monotonic = monotonic or time.monotonic
        self._wall = wall or time.time
        self._batch_size = batch_size
        # outbox_id → monotonic lease deadline for this process.
        self._held: dict[str, float] = {}
        self._last_clock_check = self._monotonic()
        self._poll_active = False

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def clock_unstable(self) -> bool:
        return self._clock.unstable

    # -- recovery ------------------------------------------------------------
    def recover_foreign_leases(self) -> int:
        """First recovery transaction: foreign LEASED rows → PENDING (§41.59.4)."""

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._conn.execute(
                "UPDATE outbox SET state='PENDING', lease_owner=NULL,"
                " lease_expires_at_us=NULL"
                " WHERE state='LEASED' AND lease_owner IS NOT ?",
                (self._instance_id,),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return cursor.rowcount

    # -- leasing ----------------------------------------------------------------
    def _maintain_clock(self) -> None:
        if self._clock.due(self._last_clock_check):
            self._clock.check()
            self._last_clock_check = self._monotonic()

    def _claim_batch(self) -> list[dict[str, Any]]:
        if self._clock.unstable:
            return []
        now_us = int(self._wall() * 1_000_000)
        deadline_us = int((self._wall() + self._lease_seconds) * 1_000_000)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self._conn.execute(
                "SELECT outbox_id, realm_id, kind, dedupe_key, payload_json,"
                " payload_hash, attempts, created_at_us FROM outbox"
                " WHERE state='PENDING' AND available_at_us <= ?"
                " ORDER BY created_at_us LIMIT ?",
                (now_us, self._batch_size),
            ).fetchall()
            claimed: list[dict[str, Any]] = []
            for row in rows:
                changed = self._conn.execute(
                    "UPDATE outbox SET state='LEASED', lease_owner=?,"
                    " lease_expires_at_us=? WHERE outbox_id=? AND state='PENDING'",
                    (self._instance_id, deadline_us, row[0]),
                )
                if changed.rowcount == 1:
                    claimed.append(
                        {
                            "outbox_id": row[0],
                            "realm_id": row[1],
                            "kind": row[2],
                            "dedupe_key": row[3],
                            "payload": json.loads(bytes(row[4]).decode("utf-8")),
                            "payload_hash": row[5],
                            "attempts": int(row[6]),
                            "created_at_us": int(row[7]),
                        }
                    )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        mono_deadline = self._monotonic() + self._lease_seconds
        for item in claimed:
            self._held[item["outbox_id"]] = mono_deadline
        return claimed

    def renew_leases(self) -> int:
        """Renew held leases (10s cadence) in wall time for takeover only."""

        if not self._held:
            return 0
        deadline_us = int((self._wall() + self._lease_seconds) * 1_000_000)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            renewed = 0
            for outbox_id in list(self._held):
                cursor = self._conn.execute(
                    "UPDATE outbox SET lease_expires_at_us=?"
                    " WHERE outbox_id=? AND state='LEASED' AND lease_owner=?",
                    (deadline_us, outbox_id, self._instance_id),
                )
                if cursor.rowcount == 1:
                    self._held[outbox_id] = self._monotonic() + self._lease_seconds
                else:
                    self._held.pop(outbox_id, None)
                renewed += cursor.rowcount
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return renewed

    # -- terminal commits (CAS) -------------------------------------------------
    def _commit_delivered(self, outbox_id: str) -> bool:
        """CAS ``LEASED``+owner → ``DELIVERED``; late owners lose (§41.59.4)."""

        if self._monotonic() > self._held.get(outbox_id, 0.0):
            return False  # monotonic deadline passed: abandon, do not commit
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._conn.execute(
                "UPDATE outbox SET state='DELIVERED', delivered_at_us=?,"
                " lease_owner=NULL, lease_expires_at_us=NULL"
                " WHERE outbox_id=? AND state='LEASED' AND lease_owner=?",
                (int(self._wall() * 1_000_000), outbox_id, self._instance_id),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return cursor.rowcount == 1

    def _abandon(self, outbox_id: str) -> None:
        """Release a held lease back to PENDING (monotonic deadline governs)."""

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE outbox SET state='PENDING', lease_owner=NULL,"
                " lease_expires_at_us=NULL"
                " WHERE outbox_id=? AND state='LEASED' AND lease_owner=?",
                (outbox_id, self._instance_id),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def _schedule_retry(self, item: dict[str, Any], error: BaseException) -> str:
        """Record the failure; retry with backoff or dead-letter (§41.38)."""

        attempts = item["attempts"] + 1
        now_us = int(self._wall() * 1_000_000)
        age = now_us - item["created_at_us"]
        dead = attempts > self._max_attempts or age >= self._dead_letter_age_us
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._conn.execute(
                "UPDATE outbox SET attempts=?, last_error_json=?,"
                " state=?, available_at_us=?, lease_owner=NULL,"
                " lease_expires_at_us=NULL"
                " WHERE outbox_id=? AND state='LEASED' AND lease_owner=?",
                (
                    attempts,
                    json.dumps({"error": "no handler registered" if isinstance(error, _MissingHandler) else "outbox delivery failed",
                                "code": error.code if isinstance(error, StableError) else ErrorCode.INTERNAL}, sort_keys=True).encode(
                        "utf-8"
                    ),
                    "DEAD_LETTER" if dead else "PENDING",
                    now_us + int(outbox_backoff_s(attempts) * 1_000_000),
                    item["outbox_id"],
                    self._instance_id,
                ),
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        if cursor.rowcount != 1:
            return "LOST_LEASE"
        return "DEAD_LETTER" if dead else "RETRY_SCHEDULED"

    # -- main loop -----------------------------------------------------------------
    def _poll_steps(self):
        """Claim a batch, deliver outside transactions, commit short CAS."""

        self._maintain_clock()
        results: list[dict[str, Any]] = []
        for item in self._claim_batch():
            outbox_id = item["outbox_id"]
            handler = self._handlers.get(item["kind"])
            if handler is None:
                self._held.pop(outbox_id, None)
                outcome = self._schedule_retry(
                    item, _MissingHandler()
                )
                results.append({"outbox_id": outbox_id, "outcome": outcome})
                continue
            try:
                yield Call(handler, (item,))
            except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
                self._abandon(outbox_id)
                self._held.pop(outbox_id, None)
                raise
            except Exception as exc:
                self._held.pop(outbox_id, None)
                outcome = self._schedule_retry(item, exc)
                results.append({"outbox_id": outbox_id, "outcome": outcome})
                continue
            delivered = self._commit_delivered(outbox_id)
            self._held.pop(outbox_id, None)
            results.append(
                {
                    "outbox_id": outbox_id,
                    "outcome": "DELIVERED" if delivered else "LOST_LEASE",
                }
            )
        return results

    def _outside_transaction(self):
        if self._conn.in_transaction:
            raise StableError(code=ErrorCode.INTERNAL, message="outbox delivery cannot await inside a transaction")

    def poll_once(self):
        if self._poll_active:
            raise StableError(code=ErrorCode.ALREADY_RUNNING, message="outbox poll already active")
        self._poll_active = True
        try:
            return drive(self._poll_steps(), before_call=self._outside_transaction)
        finally:
            self.abandon_all()
            self._poll_active = False

    async def poll_once_async(self):
        if self._poll_active:
            raise StableError(code=ErrorCode.ALREADY_RUNNING, message="outbox poll already active")
        self._poll_active = True
        try:
            return await drive_async(self._poll_steps(), before_call=self._outside_transaction)
        finally:
            self.abandon_all()
            self._poll_active = False

    def abandon_all(self) -> int:
        """Give every held lease back to PENDING (e.g. shutdown)."""

        count = 0
        for outbox_id in list(self._held):
            self._abandon(outbox_id)
            self._held.pop(outbox_id, None)
            count += 1
        return count

    # -- readiness inputs -------------------------------------------------------
    def has_critical_dead_letters(self) -> bool:
        from ..domain.outbox import CRITICAL_OUTBOX_KINDS

        placeholders = ",".join("?" for _ in CRITICAL_OUTBOX_KINDS)
        row = self._conn.execute(
            "SELECT 1 FROM outbox WHERE state='DEAD_LETTER'"
            f" AND kind IN ({placeholders}) LIMIT 1",
            tuple(sorted(CRITICAL_OUTBOX_KINDS)),
        ).fetchone()
        return row is not None

    def pending_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM outbox WHERE state IN ('PENDING','LEASED')"
        ).fetchone()
        return int(row[0])
