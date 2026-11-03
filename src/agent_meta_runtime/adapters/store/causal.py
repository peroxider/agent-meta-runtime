"""SQLite EdgeSource adapter for why/lineage causal queries (§41.35).

Reads the ``causal_edges`` projection and reports projection completeness
from the ``causal_edges`` checkpoint against the realm fact head, so the
pure traversal in ``domain.causal_query`` stays store-agnostic.
"""

from __future__ import annotations

from typing import Sequence

from ...domain.causal_query import CausalEdge
from ...domain.errors import ErrorCode, StableError

__all__ = ["SqliteEdgeSource"]


class SqliteEdgeSource:
    """Read-only edge access over the causal_edges projection."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def edges_to(self, realm_id: str, to_id: str) -> Sequence[CausalEdge]:
        rows = self._conn.execute(
            "SELECT from_id, edge_type, to_id, source_fact_id FROM causal_edges"
            " WHERE realm_id = ? AND to_id = ?",
            (realm_id, to_id),
        ).fetchall()
        return [CausalEdge(row[0], row[1], row[2], row[3]) for row in rows]

    def edges_from(self, realm_id: str, from_id: str) -> Sequence[CausalEdge]:
        rows = self._conn.execute(
            "SELECT from_id, edge_type, to_id, source_fact_id FROM causal_edges"
            " WHERE realm_id = ? AND from_id = ?",
            (realm_id, from_id),
        ).fetchall()
        return [CausalEdge(row[0], row[1], row[2], row[3]) for row in rows]

    def projection_boundary(self, realm_id: str) -> tuple[int, int]:
        realm_row = self._conn.execute(
            "SELECT next_seq FROM realms WHERE realm_id = ?", (realm_id,)
        ).fetchone()
        if realm_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="realm not found",
                details={"realm_id": realm_id},
            )
        checkpoint = self._conn.execute(
            "SELECT seq FROM checkpoints WHERE realm_id = ? AND projection = 'causal_edges'",
            (realm_id,),
        ).fetchone()
        projected = int(checkpoint[0]) if checkpoint else 0
        return projected, int(realm_row[0]) - 1
