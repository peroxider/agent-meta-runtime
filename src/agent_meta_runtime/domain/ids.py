"""Identity primitives: UUIDv7, canonical URI forms and stable names (§41.4.1).

All IDs are validated to their full canonical string form *before* reaching the
persistence layer. No URL decoding, Unicode case folding, trailing-slash
tolerance or case-insensitive comparison is performed.
"""

from __future__ import annotations

import os
import re
import threading
import time
import uuid
from dataclasses import dataclass

__all__ = [
    "ID_SCHEMES",
    "PRINCIPAL_KINDS",
    "IdError",
    "build_uri",
    "new_uuid7",
    "normalize_uuidv7",
    "parse_uri",
    "validate_stable_name",
    "validate_id",
]

ID_SCHEMES: frozenset[str] = frozenset(
    {
        "artifact",
        "blob",
        "realm",
        "epoch",
        "principal",
        "grant",
        "composition",
        "capability",
        "harness",
        "instance",
        "state",
        "state-revision",
        "fact",
        "task",
        "action",
        "invocation",
        "transaction",
        "effect-intent",
        "context",
        "proposal",
        "change-set",
        "candidate",
        "world",
        "experiment",
        "evidence",
        "evaluation",
        "operation",
        "scratch-session",
        "workspace",
    }
)

PRINCIPAL_KINDS: frozenset[str] = frozenset(
    {"operator-root", "agent", "capability", "service", "peer"}
)

_STABLE_NAME_RE = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_MAX_ID_BYTES = 255
_MAX_STABLE_NAME_BYTES = 128


class IdError(ValueError):
    """Raised when an ID string violates its canonical form."""


_MONOTONIC_LOCK = threading.Lock()
_MONOTONIC_STATE: tuple[int, int] = (0, 0)  # (now_ms, low-76-bit payload)


def new_uuid7(now_ms: int | None = None) -> str:
    """Generate a canonical lowercase RFC 9562 UUIDv7 string.

    48-bit unix-millisecond timestamp, version nibble 7, RFC 4122 variant.
    Calls without an explicit ``now_ms`` are monotonic within the same
    millisecond (RFC 9562 §6.2 monotonic random method).
    """

    global _MONOTONIC_STATE
    if now_ms is None:
        with _MONOTONIC_LOCK:
            ms = time.time_ns() // 1_000_000
            if ms <= _MONOTONIC_STATE[0]:
                ms = _MONOTONIC_STATE[0]
                low = (_MONOTONIC_STATE[1] + 1) & ((1 << 76) - 1)
            else:
                low = _random_low_76()
            _MONOTONIC_STATE = (ms, low)
    else:
        if not 0 <= now_ms < 1 << 48:
            raise IdError("unix millisecond timestamp out of UUIDv7 48-bit range")
        ms = now_ms
        low = _random_low_76()
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= low
    return str(uuid.UUID(int=value))


def _random_low_76() -> int:
    # 12-bit rand_a + 2-bit variant (10) + 62-bit rand_b, laid out in the
    # low 76 bits; the variant nibble stays 10xx because the counter starts
    # at 0b10 << 62 and wraps below 2**76.
    rand = int.from_bytes(os.urandom(10), "big")
    return (0b10 << 62) | (rand & ((1 << 62) - 1)) | ((rand >> 62) % (1 << 12)) << 64


def normalize_uuidv7(value: str) -> str:
    """Validate a UUIDv7 string and return its canonical lowercase form."""

    if not isinstance(value, str):
        raise IdError("uuid value must be str")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise IdError(f"malformed uuid: {value!r}") from exc
    if str(parsed) != value:
        raise IdError("uuid must be canonical lowercase 8-4-4-4-12 form")
    if parsed.version != 7:
        raise IdError(f"uuid version nibble must be 7, got {parsed.version}")
    if parsed.variant is not uuid.RFC_4122:
        raise IdError("uuid variant must be RFC 4122")
    return value


def validate_stable_name(value: str) -> str:
    """Validate a realm/capability stable semantic name (§41.34.1)."""

    if not isinstance(value, str) or not value:
        raise IdError("stable name must be a non-empty str")
    if not _STABLE_NAME_RE.match(value):
        raise IdError(f"invalid stable name: {value!r}")
    if len(value.encode("utf-8")) > _MAX_STABLE_NAME_BYTES:
        raise IdError("stable name exceeds 128 UTF-8 bytes")
    return value


def validate_id(value: str) -> str:
    """Validate a full ID URI per §41.4.1/§41.34.1."""

    if not isinstance(value, str) or not value:
        raise IdError("id must be a non-empty str")
    if len(value.encode("utf-8")) > _MAX_ID_BYTES:
        raise IdError("id exceeds 255 UTF-8 bytes")
    scheme, _, rest = value.partition("://")
    if not _ or not rest or scheme not in ID_SCHEMES:
        raise IdError(f"unknown or malformed id scheme: {value!r}")
    # blob/artifact use lowercase sha256 hex; principal embeds a kind segment.
    if scheme in ("artifact", "blob"):
        parts = rest.split("/")
        if len(parts) != 2 or parts[0] != "sha256" or not re.fullmatch(
            r"[0-9a-f]{64}", parts[1]
        ):
            raise IdError(f"malformed {scheme} id: {value!r}")
        return value
    if scheme == "principal":
        kind, _, ident = rest.partition("/")
        if kind not in PRINCIPAL_KINDS:
            raise IdError(f"unknown principal kind: {kind!r}")
        normalize_uuidv7(ident)
        return value
    if scheme == "context":
        parts = rest.split("/")
        if len(parts) != 2 or parts[0] != "projection":
            raise IdError(f"malformed context id: {value!r}")
        normalize_uuidv7(parts[1])
        return value
    if scheme in ("realm", "capability"):
        validate_stable_name(rest)
        return value
    normalize_uuidv7(rest)
    return value


@dataclass(frozen=True, slots=True)
class ParsedUri:
    scheme: str
    value: str


def build_uri(scheme: str, value: str) -> str:
    if scheme not in ID_SCHEMES:
        raise IdError(f"unknown id scheme: {scheme!r}")
    return f"{scheme}://{value}"


def parse_uri(value: str, expected: str | None = None) -> ParsedUri:
    validate_id(value)
    scheme, _, rest = value.partition("://")
    if expected is not None and scheme != expected:
        raise IdError(f"expected {expected}:// id, got {value!r}")
    return ParsedUri(scheme=scheme, value=rest)
