"""Runtime primitive ports (§41.3): Clock, IdGenerator, Serializer.

Ports are pure protocols over domain DTOs; adapters implement them at the edge.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["Clock", "IdGenerator", "Serializer"]


@runtime_checkable
class Clock(Protocol):
    """Time source port; all values are integer Unix microseconds."""

    def now_us(self) -> int: ...


@runtime_checkable
class IdGenerator(Protocol):
    """Identifier generator port returning canonical UUIDv7 strings."""

    def new_uuid7(self) -> str: ...


@runtime_checkable
class Serializer(Protocol):
    """Canonical serializer port for JSON-compatible values."""

    def to_canonical_bytes(self, value: Any) -> bytes: ...

    def from_json_bytes(self, data: bytes) -> Any: ...
