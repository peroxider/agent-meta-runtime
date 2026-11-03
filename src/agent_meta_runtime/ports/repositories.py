"""Store ports: Unit of Work and repository surfaces (§41.8).

The Unit of Work is the only write edge to the Meta Store. One command's
idempotency claim, canonical mutation, Facts, outbox items and meta revision
commit in a single transaction; adapters implement this protocol over SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from ..domain.envelope import JsonValue

__all__ = ["CommitResult", "FactAppendRequest", "OutboxRequest", "StoreTransaction"]


@dataclass(frozen=True)
class CommitResult:
    """Persisted result of a committed command transaction."""

    command_id: str
    transaction_id: str
    realm_id: str
    meta_revision: int
    first_seq: int
    last_seq: int
    fact_ids: tuple[str, ...]
    receipt: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True)
class FactAppendRequest:
    """Everything except chain/hash fields; the UoW allocates seq and hashes."""

    entity_type: str
    entity_id: str
    event_type: str
    schema_version: int
    payload: Mapping[str, JsonValue]
    occurred_at_us: int
    actor_id: str
    action_id: str | None = None
    transaction_id: str | None = None


@dataclass(frozen=True)
class OutboxRequest:
    kind: str
    dedupe_key: str
    payload: Mapping[str, JsonValue]
    available_at_us: int


@runtime_checkable
class StoreTransaction(Protocol):
    """Mutation facade handed to a command's aggregate mutator."""

    def append_fact(self, request: FactAppendRequest) -> str:
        """Append one fact to the realm chain; returns the fact_id."""
        ...

    def enqueue_outbox(self, request: OutboxRequest) -> str:
        """Insert one outbox item; returns the outbox_id."""
        ...

    def execute(self, sql: str, parameters: tuple = ()) -> None:
        """Run one canonical mutation statement inside the same transaction."""
        ...
