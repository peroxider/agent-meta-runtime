"""Authenticated snapshot cursors for public list/Why/Lineage queries
(§41.52).

A cursor is an opaque token the client must return verbatim: JCS payload +
HMAC-SHA256 tag under a per-daemon-launch 256-bit session key. The payload
binds the query kind, the snapshot revision / fact boundary, the last sort
key, the expiry (default 15 minutes) and, for Why traversals, the frontier
hash plus the frozen budget so a client cannot modify the budget to bypass
Authority. Tampered, expired, or cross-query cursors raise
``INVALID_ARGUMENT``; nothing about the token is parseable client-side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..domain.errors import ErrorCode, StableError

__all__ = ["CursorCodec", "DEFAULT_CURSOR_TTL_US"]

DEFAULT_CURSOR_TTL_US = 15 * 60 * 1_000_000

_PREFIX = "amcursor1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        pad = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="malformed cursor"
        ) from exc


@dataclass(frozen=True, slots=True)
class CursorCodec:
    """HMAC-sealed cursor codec bound to one daemon session key."""

    session_key: bytes
    ttl_us: int = DEFAULT_CURSOR_TTL_US

    def issue(
        self,
        *,
        kind: str,
        snapshot_revision: int,
        last_key: str,
        now_us: int,
        fact_boundary: int = 0,
        frontier_hash: str = "",
        budget: Mapping[str, Any] | None = None,
    ) -> str:
        """Seal one continuation token for ``kind`` queries."""

        payload: dict[str, Any] = {
            "kind": kind,
            "snapshot_revision": snapshot_revision,
            "fact_boundary": fact_boundary,
            "last_key": last_key,
            "expiry_us": now_us + self.ttl_us,
        }
        if frontier_hash:
            payload["frontier_hash"] = frontier_hash
        if budget is not None:
            payload["budget"] = dict(budget)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        tag = hmac.new(self.session_key, body, hashlib.sha256).digest()
        return f"{_PREFIX}.{_b64(body)}.{_b64(tag)}"

    def verify(
        self,
        cursor: str,
        *,
        kind: str,
        now_us: int,
    ) -> dict[str, Any]:
        """Open a cursor; fail closed on tamper, cross-query use or expiry."""

        if not isinstance(cursor, str) or not cursor.startswith(_PREFIX + "."):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed cursor"
            )
        parts = cursor.split(".")
        if len(parts) != 3:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed cursor"
            )
        body = _unb64(parts[1])
        tag = _unb64(parts[2])
        expected = hmac.new(self.session_key, body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="cursor authentication failed"
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed cursor"
            ) from exc
        if not isinstance(payload, dict) or payload.get("kind") != kind:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="cursor query mismatch"
            )
        if int(payload.get("expiry_us", 0)) <= now_us:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="cursor expired")
        return payload
