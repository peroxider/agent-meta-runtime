"""Long-running operations lifecycle store (§41.51, §41.46).

The ``operations`` table records accepted long-running procedures (backup,
GC plan/apply) with a dedicated command_id so outbox/projection replays stay
idempotent per procedure. Rows start RUNNING and move once to a terminal
status — the ``operation_terminal_immutable`` trigger forbids any later
UPDATE, so ``finish_operation`` refuses non-terminal rows and never
overwrites a completed outcome. Recovery marks orphaned RUNNING rows
FAILED_RECOVERY (§41.59.4); this module never re-opens them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7

__all__ = [
    "BeginOperationRequest",
    "FinishOperationRequest",
    "begin_operation",
    "finish_operation",
    "get_operation_row",
]

_TERMINAL = frozenset({"SUCCEEDED", "FAILED"})


@dataclass(frozen=True)
class BeginOperationRequest:
    kind: str
    command_id: str
    request: Mapping


@dataclass(frozen=True)
class FinishOperationRequest:
    operation_id: str
    status: str  # SUCCEEDED | FAILED
    result: Mapping | None = None
    error: Mapping | None = None


def begin_operation(txn, request: BeginOperationRequest) -> dict:
    operation_id = "operation://" + new_uuid7()
    txn._conn.execute(
        "INSERT INTO operations(operation_id, realm_id, kind, command_id, status,"
        " request_json, created_at_us, started_at_us)"
        " VALUES (?, ?, ?, ?, 'RUNNING', ?, ?, ?)",
        (
            operation_id,
            txn._envelope.realm_id,
            request.kind,
            request.command_id,
            canonical_json(dict(request.request)),
            txn.recorded_at_us,
            txn.recorded_at_us,
        ),
    )
    return {"operation_id": operation_id, "status": "RUNNING"}


def finish_operation(txn, request: FinishOperationRequest) -> dict:
    if request.status not in _TERMINAL:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="operation terminal status must be SUCCEEDED or FAILED",
            details={"status": request.status},
        )
    if (request.result is None) == (request.error is None):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="operation terminal row requires exactly one of result/error",
            details={"operation_id": request.operation_id},
        )
    row = txn._conn.execute(
        "SELECT status FROM operations WHERE operation_id = ?",
        (request.operation_id,),
    ).fetchone()
    if row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="unknown operation",
            details={"operation_id": request.operation_id},
        )
    if row[0] not in ("RUNNING", "ACCEPTED"):
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION,
            message="operation already terminal (immutable)",
            details={"operation_id": request.operation_id, "status": row[0]},
        )
    txn._conn.execute(
        "UPDATE operations SET status = ?, result_json = ?, error_json = ?,"
        " completed_at_us = ? WHERE operation_id = ?",
        (
            request.status,
            None if request.result is None else canonical_json(dict(request.result)),
            None if request.error is None else canonical_json(dict(request.error)),
            txn.recorded_at_us,
            request.operation_id,
        ),
    )
    return {"operation_id": request.operation_id, "status": request.status}


def get_operation_row(conn, operation_id: str) -> dict | None:
    row = conn.execute(
        "SELECT operation_id, realm_id, kind, command_id, status, request_json,"
        " result_json, error_json, created_at_us, started_at_us, completed_at_us"
        " FROM operations WHERE operation_id = ?",
        (operation_id,),
    ).fetchone()
    if row is None:
        return None
    import json

    return {
        "operation_id": row[0],
        "realm_id": row[1],
        "kind": row[2],
        "command_id": row[3],
        "status": row[4],
        "request": json.loads(row[5]) if row[5] else {},
        "result": json.loads(row[6]) if row[6] else None,
        "error": json.loads(row[7]) if row[7] else None,
        "created_at_us": row[8],
        "started_at_us": row[9],
        "completed_at_us": row[10],
    }
