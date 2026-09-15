"""Canonical encoding: RFC 8785 JCS, SHA-256 helpers and time primitives.

Rules (§41.34.1):
- JSON integers are restricted to IEEE-754 safe integers
  ``[-9007199254740991, 9007199254740991]``; larger int64/uint64 values must be
  carried as canonical decimal strings by the schema.
- Non-finite numbers and ``-0`` semantics are rejected.
- Strings keep original Unicode code points (no NFC/NFD folding).
- Times are Unix microseconds; durations/deadlines use integers, never float
  seconds participating in hashes.
- Object keys are sorted by their UTF-16 code units (RFC 8785 §3.2.3).
"""

from __future__ import annotations

import hashlib
import math
import time
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "CanonicalJsonError",
    "SAFE_INT_MAX",
    "SAFE_INT_MIN",
    "canonical_json",
    "canonical_json_str",
    "now_us",
    "payload_hash",
    "rfc3339",
    "sha256_hex",
]

SAFE_INT_MAX = 9007199254740991
SAFE_INT_MIN = -9007199254740991


class CanonicalJsonError(ValueError):
    """Raised when a value cannot be canonicalized under RFC 8785 / I-JSON."""


def _check_safe_int(value: int) -> None:
    if not SAFE_INT_MIN <= value <= SAFE_INT_MAX:
        raise CanonicalJsonError(
            f"integer {value} outside IEEE-754 safe range; encode as canonical "
            "decimal string per schema"
        )


def _sort_key(key: str) -> bytes:
    # RFC 8785 sorts keys by UTF-16 code units; UTF-16-BE byte order gives the
    # same ordering.
    return key.encode("utf-16-be", "surrogatepass")


def _format_double(value: float) -> str:
    """Format a finite double per ECMAScript Number::toString (RFC 8785 §3.2.2.3)."""

    if math.isnan(value) or math.isinf(value):
        raise CanonicalJsonError("non-finite number is not representable in JSON")
    if value == 0.0:
        # -0 must never be emitted; canonical form of both zeros is "0".
        return "0"
    sign = "-" if value < 0 else ""
    text = repr(abs(value))
    if "e" in text or "E" in text:
        mantissa, _, exp_text = text.replace("E", "e").partition("e")
        exponent = int(exp_text)
    else:
        mantissa, exponent = text, 0
    if "." in mantissa:
        int_part, _, frac_part = mantissa.partition(".")
    else:
        int_part, frac_part = mantissa, ""
    stripped_int = int_part.lstrip("0")
    if stripped_int:
        n = len(stripped_int) + exponent
    else:
        # Pure-fraction mantissa (repr only produces this with exponent 0):
        # the first significant digit sits at 10**(exponent - leading_zeros),
        # and n - 1 is that position.
        leading = len(frac_part) - len(frac_part.lstrip("0"))
        n = exponent - leading
    digits = (int_part + frac_part).lstrip("0").rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exp = n - 1
    mant = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + mant + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        _check_safe_int(value)
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_format_double(value))
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise CanonicalJsonError("object keys must be strings")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_sort_key)):
            if index:
                out.append(",")
            out.append(_serialize_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    else:
        raise CanonicalJsonError(f"type {type(value).__name__} is not JSON value")


_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _serialize_string(value: str) -> str:
    pieces: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if code in _ESCAPES:
            pieces.append(_ESCAPES[code])
        elif code < 0x20:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(ch)
    pieces.append('"')
    return "".join(pieces)


def canonical_json_str(value: Any) -> str:
    """Serialize a JSON value to its RFC 8785 canonical string form."""

    out: list[str] = []
    _serialize(value, out)
    return "".join(out)


def canonical_json(value: Any) -> bytes:
    """Serialize a JSON value to canonical UTF-8 bytes."""

    return canonical_json_str(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase 64-char SHA-256 hex digest."""

    return hashlib.sha256(data).hexdigest()


def payload_hash(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``value``."""

    return sha256_hex(canonical_json(value))


def now_us() -> int:
    """Current Unix time in microseconds."""

    return time.time_ns() // 1_000


def rfc3339(us: int) -> str:
    """Render Unix microseconds as UTC RFC 3339 with microsecond precision."""

    if not isinstance(us, int):
        raise CanonicalJsonError("time must be integer microseconds")
    seconds, micros = divmod(us, 1_000_000)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=micros)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
