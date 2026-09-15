"""Store initialization: migration application and identity checks (§41.34.2).

Startup rejects a writer when ``application_id``/``user_version`` do not
match the frozen values or when ``schema_migrations`` is not a contiguous
version chain whose checksums match the migration bytes.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ... import __version__
from ...domain.canonical import now_us
from ...domain.errors import ErrorCode, StableError
from .connection import APPLICATION_ID, USER_VERSION, connect_store
from .migrations import (
    MIGRATION_CHECKSUM,
    MIGRATION_NAME,
    MIGRATION_SQL,
    MIGRATION_VERSION,
)

__all__ = [
    "initialize_store",
    "verify_store_identity",
    "verify_migration_chain",
]


def verify_migration_chain(conn: sqlite3.Connection) -> None:
    """Validate the contiguous, checksum-matching migration chain."""

    rows = conn.execute(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    for index, (version, name, checksum) in enumerate(rows, start=1):
        if version != index:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message=(
                    "migration versions must be contiguous, "
                    f"got {version} at position {index}"
                ),
            )
        if name == MIGRATION_NAME and checksum != MIGRATION_CHECKSUM:
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message=f"migration {name} checksum drift",
            )


def verify_store_identity(conn: sqlite3.Connection) -> None:
    """Reject any connection whose store identity does not match v0.1."""

    application_id = conn.execute("PRAGMA application_id").fetchone()[0]
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    if application_id != APPLICATION_ID or user_version != USER_VERSION:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message=(
                "store identity mismatch: "
                f"application_id={application_id} user_version={user_version}"
            ),
        )
    verify_migration_chain(conn)


def initialize_store(db_path: Path) -> sqlite3.Connection:
    """Apply the v0.1 authoritative DDL and freeze the store identity."""

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect_store(db_path)
    try:
        conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version = {USER_VERSION}")
        # executescript is the only way to run multi-statement DDL (triggers
        # included); wrapping it in BEGIN IMMEDIATE/COMMIT keeps it atomic.
        conn.executescript("BEGIN IMMEDIATE;\n" + MIGRATION_SQL + "\nCOMMIT;")
        conn.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at_us,"
            " runtime_version) VALUES (?, ?, ?, ?, ?)",
            (
                MIGRATION_VERSION,
                MIGRATION_NAME,
                MIGRATION_CHECKSUM,
                now_us(),
                __version__,
            ),
        )
        conn.commit()
        verify_store_identity(conn)
    except BaseException:
        conn.close()
        raise
    return conn
