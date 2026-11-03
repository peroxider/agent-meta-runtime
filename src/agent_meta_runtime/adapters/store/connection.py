"""SQLite connection profile with busy deadline backoff (§41.34.2).

Every writer/reader connection executes and verifies the frozen PRAGMA
profile. Writers use ``BEGIN IMMEDIATE``; ``BUSY/LOCKED`` is retried with
25/50/100/200/400 ms full-jitter backoff inside the caller's deadline and
then surfaced as ``RESOURCE_EXHAUSTED`` — never retried forever.
"""

from __future__ import annotations

import random
import sqlite3
import time
from pathlib import Path
from typing import Callable, TypeVar

from ...domain.deadline import Deadline
from ...domain.errors import ErrorCode, StableError
from ...domain.meta_schema import META_SCHEMA_VERSION

__all__ = [
    "APPLICATION_ID",
    "USER_VERSION",
    "PRAGMA_PROFILE",
    "apply_pragma_profile",
    "begin_immediate_with_retry",
    "busy_retry",
    "connect_store",
]

APPLICATION_ID = 1095586388  # ASCII "AMRT"
USER_VERSION = META_SCHEMA_VERSION

PRAGMA_PROFILE: tuple[tuple[str, str], ...] = (
    ("foreign_keys", "ON"),
    ("journal_mode", "wal"),
    ("synchronous", "FULL"),
    ("busy_timeout", "5000"),
    ("trusted_schema", "OFF"),
    ("recursive_triggers", "ON"),
)

# SQLite reports some pragmas numerically: ON/OFF as 1/0, FULL as 2.
_PRAGMA_VALUE_ALIASES = {"on": "1", "off": "0", "full": "2"}

_BACKOFF_SLOTS_MS = (25, 50, 100, 200, 400)

T = TypeVar("T")


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def busy_retry(
    operation: Callable[[], T],
    *,
    deadline: Deadline,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> T:
    """Run ``operation`` retrying BUSY/LOCKED within ``deadline``."""

    rng = rng or random.Random()
    attempt = 0
    while True:
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not _is_busy(exc):
                raise
            if not deadline.remaining_us:
                raise StableError(
                    code=ErrorCode.RESOURCE_EXHAUSTED,
                    message="store busy deadline exceeded",
                    details={"deadline_remaining_us": 0},
                ) from exc
            slot_ms = _BACKOFF_SLOTS_MS[min(attempt, len(_BACKOFF_SLOTS_MS) - 1)]
            attempt += 1
            delay_s = rng.uniform(0, slot_ms) / 1_000
            budget_s = deadline.remaining_us / 1_000_000
            if delay_s > budget_s:
                sleep(budget_s)
            else:
                sleep(delay_s)


def apply_pragma_profile(conn: sqlite3.Connection, busy_timeout_ms: int = 5000) -> None:
    """Execute and verify the §41.34.2 PRAGMA profile on ``conn``."""

    for pragma, expected in PRAGMA_PROFILE:
        if pragma == "busy_timeout":
            expected = str(int(busy_timeout_ms))
            conn.execute(f"PRAGMA busy_timeout = {expected}")
        else:
            conn.execute(f"PRAGMA {pragma} = {expected}")
        got = str(conn.execute(f"PRAGMA {pragma}").fetchone()[0]).lower()
        expected_norm = str(expected).lower()
        got = _PRAGMA_VALUE_ALIASES.get(got, got)
        expected_norm = _PRAGMA_VALUE_ALIASES.get(expected_norm, expected_norm)
        if got != expected_norm:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message=f"pragma {pragma} is {got!r}, expected {expected!r}",
            )


def connect_store(
    db_path: Path | str,
    *,
    busy_timeout_ms: int = 5000,
    isolation_level: str | None = None,
) -> sqlite3.Connection:
    """Open a store connection and apply the frozen PRAGMA profile.

    ``isolation_level=None`` puts python-sqlite into manual transaction
    control so ``BEGIN IMMEDIATE`` is issued explicitly.
    """

    conn = sqlite3.connect(
        str(db_path), timeout=busy_timeout_ms / 1000, isolation_level=isolation_level
    )
    try:
        apply_pragma_profile(conn, busy_timeout_ms=busy_timeout_ms)
    except StableError:
        conn.close()
        raise
    return conn


def begin_immediate_with_retry(conn: sqlite3.Connection, deadline: Deadline) -> None:
    """``BEGIN IMMEDIATE`` with BUSY backoff inside ``deadline``."""

    busy_retry(lambda: conn.execute("BEGIN IMMEDIATE"), deadline=deadline)
