"""System-backed adapters for the Clock/IdGenerator/Serializer ports."""

from __future__ import annotations

import json
from typing import Any

from ..domain.canonical import CanonicalJsonError, canonical_json, now_us
from ..domain.ids import new_uuid7

__all__ = ["CanonicalJsonSerializer", "SystemClock", "SystemIdGenerator"]


class SystemClock:
    """Wall-clock adapter; every call returns integer Unix microseconds."""

    def now_us(self) -> int:
        return now_us()


class SystemIdGenerator:
    """CSPRNG-backed UUIDv7 generator."""

    def new_uuid7(self) -> str:
        return new_uuid7()


class CanonicalJsonSerializer:
    """JCS serializer adapter; fails closed on non-canonicalizable values."""

    def to_canonical_bytes(self, value: Any) -> bytes:
        try:
            return canonical_json(value)
        except CanonicalJsonError as exc:
            raise ValueError(str(exc)) from exc

    def from_json_bytes(self, data: bytes) -> Any:
        try:
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid canonical JSON bytes: {exc}") from exc
