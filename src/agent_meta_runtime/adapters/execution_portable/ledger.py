"""Portable Backend durable request ledger (§41.48.2).

An independent ``<data_dir>/backend/portable.db`` — never a Meta Store table.
Same crash profile as the Meta DB (WAL, synchronous FULL), but
``application_id=1095582276`` (ASCII ``AMBD``) and ``user_version=1`` with the
fixed DDL from the spec. The Submit flow runs ``BEGIN IMMEDIATE``: an absent
request inserts ``PREPARED``, the same request/hash returns the stored
record, and a different hash is an ``IDEMPOTENCY_CONFLICT``.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError

__all__ = [
    "PORTABLE_DB_APPLICATION_ID",
    "PORTABLE_DB_USER_VERSION",
    "PortableRequestLedger",
    "REQUEST_STATES",
]

PORTABLE_DB_APPLICATION_ID = 1095582276  # ASCII 'AMBD'
PORTABLE_DB_USER_VERSION = 1
REQUEST_STATES = ("PREPARED", "CLAIMED", "RUNNING", "TERMINAL", "UNKNOWN")

_DDL = """
CREATE TABLE IF NOT EXISTS backend_meta (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), backend_id TEXT NOT NULL,
  generation INTEGER NOT NULL, created_at_us INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS requests (
  request_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, operation_kind TEXT NOT NULL,
  payload_hash TEXT NOT NULL, payload_jcs BLOB NOT NULL,
  idempotency_class TEXT NOT NULL, reversibility TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PREPARED','CLAIMED','RUNNING','TERMINAL','UNKNOWN')),
  handle_bytes BLOB NOT NULL, request_relpath TEXT NOT NULL UNIQUE,
  worker_pid INTEGER, worker_start_identity TEXT, launch_nonce_hash TEXT,
  result_hash TEXT, result_jcs BLOB, effect_state_unknown INTEGER NOT NULL DEFAULT 0,
  terminal_acknowledged INTEGER NOT NULL DEFAULT 0,
  created_at_us INTEGER NOT NULL, started_at_us INTEGER, completed_at_us INTEGER,
  retained_until_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL,
  CHECK(NOT(state='TERMINAL' AND result_jcs IS NULL)),
  CHECK(effect_state_unknown IN (0,1)), CHECK(terminal_acknowledged IN (0,1))
) STRICT;
CREATE TABLE IF NOT EXISTS request_events (
  request_id TEXT NOT NULL, ordinal INTEGER NOT NULL, event_type TEXT NOT NULL,
  event_jcs BLOB NOT NULL, occurred_at_us INTEGER NOT NULL,
  PRIMARY KEY(request_id, ordinal), FOREIGN KEY(request_id) REFERENCES requests(request_id)
) STRICT;
CREATE INDEX IF NOT EXISTS ix_requests_recovery ON requests(state, updated_at_us);
CREATE INDEX IF NOT EXISTS ix_requests_retention ON requests(terminal_acknowledged, retained_until_us);
"""

_COLUMNS = (
    "request_id, realm_id, operation_kind, payload_hash, payload_jcs,"
    " idempotency_class, reversibility, state, handle_bytes, request_relpath,"
    " worker_pid, worker_start_identity, launch_nonce_hash, result_hash,"
    " result_jcs, effect_state_unknown, terminal_acknowledged, created_at_us,"
    " started_at_us, completed_at_us, retained_until_us, updated_at_us"
)


class PortableRequestLedger:
    """Durable request ledger over ``portable.db`` (§41.48.2)."""

    def __init__(self, path: str, *, backend_id: str = "backend://portable") -> None:
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        # executescript commits any open transaction, so schema creation runs
        # outside an explicit one; each DDL statement is idempotent.
        self._conn.executescript(_DDL)
        self._conn.execute(f"PRAGMA application_id={int(PORTABLE_DB_APPLICATION_ID)}")
        self._conn.execute(f"PRAGMA user_version={int(PORTABLE_DB_USER_VERSION)}")
        self.backend_id = backend_id

    def close(self) -> None:
        self._conn.close()

    # -- internal helpers --------------------------------------------------------
    def _ensure_meta(self, now_us: int) -> None:
        row = self._conn.execute("SELECT COUNT(*) FROM backend_meta").fetchone()
        if row[0] == 0:
            self._conn.execute(
                "INSERT INTO backend_meta(singleton, backend_id, generation,"
                " created_at_us) VALUES (1, ?, 1, ?)",
                (self.backend_id, now_us),
            )

    def _row_to_dict(self, row: tuple) -> dict[str, Any]:
        keys = [c.strip() for c in _COLUMNS.split(",")]
        return dict(zip(keys, row))

    def get(self, request_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            f"SELECT {_COLUMNS} FROM requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def _append_event(
        self, request_id: str, event_type: str, event: dict[str, Any], now_us: int
    ) -> None:
        ordinal = self._conn.execute(
            "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM request_events WHERE request_id = ?",
            (request_id,),
        ).fetchone()[0]
        self._conn.execute(
            "INSERT INTO request_events(request_id, ordinal, event_type,"
            " event_jcs, occurred_at_us) VALUES (?, ?, ?, ?, ?)",
            (request_id, ordinal, event_type, canonical_json(event), now_us),
        )

    # -- submit --------------------------------------------------------------------
    def submit(
        self,
        *,
        request_id: str,
        realm_id: str,
        operation_kind: str,
        payload_hash: str,
        payload_jcs: bytes,
        idempotency_class: str,
        reversibility: str,
        request_relpath: str,
        now_us: int,
        requested_retention_us: int,
    ) -> dict[str, Any]:
        """Idempotent Submit under ``BEGIN IMMEDIATE`` (§41.48.2).

        Returns the stored record dict (``created`` flag True for a fresh
        insert). Raises ``IDEMPOTENCY_CONFLICT`` on a hash mismatch for the
        same request id.
        """

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._ensure_meta(now_us)
            row = self._conn.execute(
                f"SELECT {_COLUMNS} FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                record = self._row_to_dict(row)
                if record["payload_hash"] != payload_hash:
                    raise StableError(
                        code=ErrorCode.IDEMPOTENCY_CONFLICT,
                        message="same request id with a different payload hash",
                        details={"request_id": request_id},
                    )
                self._conn.execute("COMMIT")
                record["created"] = False
                return record
            handle_bytes = uuid.uuid4().bytes
            self._conn.execute(
                "INSERT INTO requests(request_id, realm_id, operation_kind,"
                " payload_hash, payload_jcs, idempotency_class, reversibility,"
                " state, handle_bytes, request_relpath, created_at_us,"
                " retained_until_us, updated_at_us)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?, ?, ?, ?)",
                (
                    request_id,
                    realm_id,
                    operation_kind,
                    payload_hash,
                    payload_jcs,
                    idempotency_class,
                    reversibility,
                    handle_bytes,
                    request_relpath,
                    now_us,
                    now_us + max(requested_retention_us, 0),
                    now_us,
                ),
            )
            self._append_event(
                request_id, "submitted", {"payload_hash": payload_hash}, now_us
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        record = self.get(request_id)
        assert record is not None
        record["created"] = True
        return record

    # -- lifecycle transitions --------------------------------------------------------
    def mark_claimed(
        self,
        request_id: str,
        *,
        worker_pid: int,
        worker_start_identity: str,
        launch_nonce_hash: str,
        now_us: int,
    ) -> None:
        """Worker claimed the request (claim observed by the parent)."""

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT state FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise StableError(code=ErrorCode.NOT_FOUND, message="unknown request")
            if row[0] in ("TERMINAL", "UNKNOWN"):
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION,
                    message=f"request already {row[0]}",
                )
            self._conn.execute(
                "UPDATE requests SET state='CLAIMED', worker_pid=?,"
                " worker_start_identity=?, launch_nonce_hash=?, updated_at_us=?"
                " WHERE request_id = ?",
                (
                    worker_pid,
                    worker_start_identity,
                    launch_nonce_hash,
                    now_us,
                    request_id,
                ),
            )
            self._append_event(request_id, "claimed", {"worker_pid": worker_pid}, now_us)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def mark_running(self, request_id: str, *, now_us: int) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE requests SET state='RUNNING', started_at_us=?, updated_at_us=?"
                " WHERE request_id = ? AND state IN ('PREPARED','CLAIMED')",
                (now_us, now_us, request_id),
            )
            self._append_event(request_id, "started", {}, now_us)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def mark_terminal(
        self,
        request_id: str,
        *,
        result_hash: str,
        result_jcs: bytes,
        effect_state_unknown: bool = False,
        now_us: int,
    ) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT state, result_hash FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise StableError(code=ErrorCode.NOT_FOUND, message="unknown request")
            if row[0] == "TERMINAL":
                # Idempotent terminal record: same hash replays, mismatch refuses.
                if row[1] != result_hash:
                    raise StableError(
                        code=ErrorCode.REVISION_CONFLICT,
                        message="terminal result hash mismatch",
                    )
                self._conn.execute("COMMIT")
                return
            self._conn.execute(
                "UPDATE requests SET state='TERMINAL', result_hash=?, result_jcs=?,"
                " effect_state_unknown=?, completed_at_us=?, updated_at_us=?"
                " WHERE request_id = ?",
                (
                    result_hash,
                    result_jcs,
                    1 if effect_state_unknown else 0,
                    now_us,
                    now_us,
                    request_id,
                ),
            )
            self._append_event(
                request_id, "terminal", {"result_hash": result_hash}, now_us
            )
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def mark_unknown(self, request_id: str, *, now_us: int, reason: str) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT state FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise StableError(code=ErrorCode.NOT_FOUND, message="unknown request")
            if row[0] == "TERMINAL":
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="already terminal"
                )
            self._conn.execute(
                "UPDATE requests SET state='UNKNOWN', effect_state_unknown=1,"
                " updated_at_us=? WHERE request_id = ?",
                (now_us, request_id),
            )
            self._append_event(request_id, "unknown", {"reason": reason}, now_us)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    def acknowledge_terminal(
        self,
        request_id: str,
        *,
        result_hash: str,
        retained_until_us: int,
        now_us: int,
    ) -> int:
        """Hash-checked, replay-safe acknowledgement; returns retained_until."""

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT state, result_hash, terminal_acknowledged, retained_until_us"
                " FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise StableError(code=ErrorCode.NOT_FOUND, message="unknown request")
            state, stored_hash, acknowledged, stored_until = row
            if state != "TERMINAL":
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="request not terminal"
                )
            if result_hash != stored_hash:
                raise StableError(
                    code=ErrorCode.REVISION_CONFLICT,
                    message="acknowledgement hash mismatch",
                )
            if acknowledged:
                self._conn.execute("COMMIT")
                return int(stored_until)
            self._conn.execute(
                "UPDATE requests SET terminal_acknowledged=1, retained_until_us=?,"
                " updated_at_us=? WHERE request_id = ?",
                (retained_until_us, now_us, request_id),
            )
            self._append_event(request_id, "acknowledged", {}, now_us)
            self._conn.execute("COMMIT")
            return retained_until_us
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise

    # -- recovery / reconcile ---------------------------------------------------------
    def recovery_candidates(self) -> list[dict[str, Any]]:
        """Non-terminal requests ordered for recovery (§41.48.2)."""

        rows = self._conn.execute(
            f"SELECT {_COLUMNS} FROM requests WHERE state IN"
            " ('PREPARED','CLAIMED','RUNNING','UNKNOWN') ORDER BY updated_at_us"
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def events(self, request_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT ordinal, event_type, event_jcs, occurred_at_us FROM request_events"
            " WHERE request_id = ? ORDER BY ordinal",
            (request_id,),
        ).fetchall()
        return [
            {
                "ordinal": r[0],
                "event_type": r[1],
                "event_jcs": bytes(r[2]),
                "occurred_at_us": r[3],
            }
            for r in rows
        ]

    def sweep_expired(self, now_us: int) -> list[str]:
        """Acknowledged terminal request ids past retention (auditable cleanup
        plan input; the ledger only lists them)."""

        rows = self._conn.execute(
            "SELECT request_id FROM requests WHERE terminal_acknowledged = 1"
            " AND retained_until_us < ?",
            (now_us,),
        ).fetchall()
        return [r[0] for r in rows]
