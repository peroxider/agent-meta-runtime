"""Why/lineage causal traversal (§41.35, FR-MREF-002).

Pure graph algorithms over the ``causal_edges`` projection. ``why`` walks
reverse from a subject through cause-type edges; ``lineage`` walks forward
through result/derivation edges. Both are budget-bounded (depth 8, 500 nodes,
1 MiB explanation bytes by default) and return a truncation flag with an
opaque continuation cursor instead of an unbounded result. The store adapter
supplies edges; this module owns only traversal semantics.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Protocol, Sequence

from .canonical import canonical_json
from .fact_catalog import LINEAGE_EDGE_TYPES, WHY_EDGE_TYPES
from .ids import validate_id

__all__ = [
    "CausalEdge",
    "CausalExplanation",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_NODES",
    "EdgeSource",
    "lineage",
    "why",
]

DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_NODES = 500
DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB explanation budget


class CausalEdge:
    """One projected edge; ``source_fact_id`` is mandatory (FR-MFACT-005)."""

    __slots__ = ("from_id", "edge_type", "to_id", "source_fact_id", "seq")

    def __init__(
        self,
        from_id: str,
        edge_type: str,
        to_id: str,
        source_fact_id: str,
        seq: int = 0,
    ) -> None:
        self.from_id = from_id
        self.edge_type = edge_type
        self.to_id = to_id
        self.source_fact_id = source_fact_id
        self.seq = seq


class EdgeSource(Protocol):
    """Adapter-supplied read access to projected edges and fact boundary."""

    def edges_to(self, realm_id: str, to_id: str) -> Sequence[CausalEdge]: ...

    def edges_from(self, realm_id: str, from_id: str) -> Sequence[CausalEdge]: ...

    def projection_boundary(self, realm_id: str) -> tuple[int, int]:
        """(projected_seq, current_fact_seq) for completeness reporting."""
        ...


@dataclass(frozen=True, slots=True)
class CausalExplanation:
    root_id: str
    realm_id: str
    nodes: tuple[str, ...]
    edges: tuple[tuple[str, str, str, str], ...]  # from, type, to, source fact
    direction: str  # "why" (reverse) or "lineage" (forward)
    truncated: bool
    continuation_cursor: str | None
    projection_seq: int
    current_fact_seq: int
    consumed: dict = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """A projection behind the current fact head cannot claim completeness."""

        return not self.truncated and self.projection_seq >= self.current_fact_seq


def _encode_state(
    visited: Sequence[str], seen: set[str], frontier: Sequence[str], depth: int
) -> str:
    payload = canonical_json(
        {
            "visited": list(visited),
            "seen": sorted(seen),
            "frontier": list(frontier),
            "depth": depth,
        }
    )
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_state(cursor: str) -> tuple[list[str], set[str], list[str], int]:
    payload = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
    return (
        [str(x) for x in payload["visited"]],
        {str(x) for x in payload["seen"]},
        [str(x) for x in payload["frontier"]],
        int(payload["depth"]),
    )


def _traverse(
    source: EdgeSource,
    realm_id: str,
    root_id: str,
    *,
    direction: str,
    edge_types: frozenset[str],
    max_depth: int,
    max_nodes: int,
    max_bytes: int,
    cursor: str | None,
) -> CausalExplanation:
    validate_id(realm_id)
    validate_id(root_id)
    if direction == "why":
        # Reverse walk: incident edges point *to* the current node; the
        # visited counterpart is the subject (from_id) that caused it.
        adjacency, counterpart_of = source.edges_to, lambda e: e.from_id
    elif direction == "lineage":
        adjacency, counterpart_of = source.edges_from, lambda e: e.to_id
    else:
        raise ValueError("direction must be 'why' or 'lineage'")

    if cursor is None:
        visited: list[str] = []
        seen: set[str] = {root_id}
        frontier: list[str] = [root_id]
        depth = 0
    else:
        visited, seen, frontier, depth = _decode_state(cursor)
    byte_budget = max_bytes

    edges_out: list[tuple[str, str, str, str]] = []
    truncated = False

    while frontier and depth < max_depth and len(visited) < max_nodes:
        next_frontier: list[str] = []
        for node in frontier:
            if len(visited) >= max_nodes:
                truncated = True
                break
            visited.append(node)
            incident = sorted(
                (e for e in adjacency(realm_id, node) if e.edge_type in edge_types),
                key=lambda e: (e.edge_type, counterpart_of(e)),
            )
            for edge in incident:
                cost = (
                    len(edge.from_id)
                    + len(edge.edge_type)
                    + len(edge.to_id)
                    + len(edge.source_fact_id)
                    + 4
                )
                if byte_budget - cost < 0:
                    truncated = True
                    break
                byte_budget -= cost
                edges_out.append(
                    (edge.from_id, edge.edge_type, edge.to_id, edge.source_fact_id)
                )
                counterpart = counterpart_of(edge)
                if counterpart not in seen:
                    seen.add(counterpart)
                    next_frontier.append(counterpart)
            if truncated:
                break
        if truncated:
            if visited and visited[-1] is node:
                visited.pop()  # un-process; it resumes at the frontier head
            frontier = [node] + [n for n in next_frontier if n != node]
            break
        frontier = next_frontier
        depth += 1

    if frontier and not truncated:
        # Stopped at depth/node budget with unexpanded frontier remaining.
        truncated = True

    continuation = None
    if truncated and frontier:
        continuation = _encode_state(visited, seen, frontier, depth)

    projection_seq, current_fact_seq = source.projection_boundary(realm_id)
    return CausalExplanation(
        root_id=root_id,
        realm_id=realm_id,
        nodes=tuple(visited),
        edges=tuple(edges_out),
        direction=direction,
        truncated=truncated,
        continuation_cursor=continuation,
        projection_seq=projection_seq,
        current_fact_seq=current_fact_seq,
        consumed={
            "depth": depth,
            "nodes": len(visited),
            "bytes": max_bytes - byte_budget,
        },
    )


def why(
    source: EdgeSource,
    realm_id: str,
    entity_id: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    cursor: str | None = None,
) -> CausalExplanation:
    """Reverse traversal: what caused this entity (§41.35 why)."""

    return _traverse(
        source,
        realm_id,
        entity_id,
        direction="why",
        edge_types=WHY_EDGE_TYPES,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_bytes=max_bytes,
        cursor=cursor,
    )


def lineage(
    source: EdgeSource,
    realm_id: str,
    entity_id: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    cursor: str | None = None,
) -> CausalExplanation:
    """Forward traversal: what derived from this entity."""

    return _traverse(
        source,
        realm_id,
        entity_id,
        direction="lineage",
        edge_types=LINEAGE_EDGE_TYPES,
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_bytes=max_bytes,
        cursor=cursor,
    )
