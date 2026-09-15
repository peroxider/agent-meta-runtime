"""Backend v1 wire layer (§41.27, §41.41, §41.14): method registry, payload
hashing, error mapping, version/feature negotiation, and authority-token
redaction on top of the frozen protobuf modules.

The generated modules under :mod:`agent_meta_runtime.protocols._v1` carry the
frozen field numbers; this module owns the v1 *semantics*: the eight backend
session methods, the ``payload_hash = sha256(payload_jcs)`` lowercase rule,
``StableError`` ↔ ``RpcError`` mapping with fixed retryability, deterministic
version-range intersection for ``Negotiate``, trace-key validation, and the
``AuthorityToken`` wrapper whose repr never leaks token bytes.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Iterable

from ..domain.canonical import canonical_json
from ..domain.errors import ErrorCode, RETRYABLE_CODES, StableError
from ..domain.ids import new_uuid7
from ._v1 import transport_pb2 as transport

__all__ = [
    "BACKEND_METHODS",
    "TRANSPORT_MAJOR",
    "TRANSPORT_MINOR",
    "AuthorityToken",
    "backend_error",
    "build_envelope",
    "error_from_rpc",
    "error_to_rpc",
    "negotiate_version",
    "new_request_id",
    "payload_hash",
    "select_features",
    "validate_trace",
]

TRANSPORT_MAJOR = 1
TRANSPORT_MINOR = 0

#: The eight frozen backend session RPCs (§41.27).
BACKEND_METHODS: tuple[str, ...] = tuple(
    f"agent_meta.execution_backend.v1.Backend.{name}"
    for name in (
        "Negotiate",
        "Submit",
        "Await",
        "Cancel",
        "Inspect",
        "Reconcile",
        "AcknowledgeTerminal",
        "CloseSession",
    )
)

_DETAIL_RETRY_HINT = "retryable_hint"


def new_request_id() -> str:
    """UUIDv7 request id for the envelope and backend request identity."""

    return new_uuid7()


def payload_hash(payload_jcs: bytes) -> str:
    """Lowercase SHA-256 hex of the canonical payload bytes (§41.41)."""

    return hashlib.sha256(payload_jcs).hexdigest()


class AuthorityToken:
    """Enforcement-only wrapper for ``authority_token`` bytes.

    The token is passed to the enforcement layer and then dropped; it is
    never logged or serialized into Facts, and every string conversion
    renders ``[REDACTED]`` (§41.41).
    """

    __slots__ = ("_bytes",)

    def __init__(self, raw: bytes) -> None:
        self._bytes = bytes(raw)

    @property
    def raw(self) -> bytes:
        return self._bytes

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "[REDACTED]"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AuthorityToken):
            return secrets.compare_digest(self._bytes, other._bytes)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._bytes)


def build_envelope(
    *,
    method: str,
    payload: bytes | None = None,
    error: transport.RpcError | None = None,
    is_response: bool = False,
    request_id: str | None = None,
    deadline_at_us: int = 0,
    trace: dict[str, str] | None = None,
) -> transport.RpcEnvelope:
    """Build a v1 envelope with the fixed protocol major and a fresh UUIDv7."""

    envelope = transport.RpcEnvelope(
        protocol_major=TRANSPORT_MAJOR,
        protocol_minor=TRANSPORT_MINOR,
        request_id=request_id or new_request_id(),
        method=method,
        deadline_at_us=deadline_at_us,
        is_response=is_response,
    )
    if trace:
        envelope.trace.update(validate_trace(trace))
    if payload is not None and error is not None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="envelope body must be payload xor error",
        )
    if payload is not None:
        envelope.payload = payload
    if error is not None:
        envelope.error.CopyFrom(error)
    return envelope


_TRACE_KEYS = frozenset({"traceparent", "tracestate"})


def validate_trace(trace: dict[str, str]) -> dict[str, str]:
    """Only ``traceparent``/``tracestate`` may appear in the trace map."""

    unknown = sorted(set(trace) - _TRACE_KEYS)
    if unknown:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="trace map only allows traceparent/tracestate",
            details={"keys": unknown},
        )
    return dict(trace)


def error_to_rpc(
    exc: StableError, *, correlation_id: str = "", schema_version: int = 1
) -> transport.RpcError:
    """Map a stable error onto the frozen ``RpcError`` wire shape (§41.14).

    Conditional retryability (``None``) is rendered as ``retryable=false`` on
    the wire with an explicit hint in the typed details, so retry policy can
    still honor the registry.
    """

    rpc = transport.RpcError(
        code=exc.code,
        retryable=bool(RETRYABLE_CODES.get(exc.code, False)),
        message_safe=exc.message,
        details_schema_version=schema_version,
        details_jcs=canonical_json(exc.details),
        correlation_id=correlation_id,
    )
    if RETRYABLE_CODES.get(exc.code) is None:
        rpc.details_jcs = canonical_json(
            {**exc.details, _DETAIL_RETRY_HINT: "conditional"}
        )
    return rpc


def error_from_rpc(rpc: transport.RpcError) -> StableError:
    """Rebuild a ``StableError`` from the wire shape; unknown codes fail."""

    if rpc.code not in ErrorCode.ALL:
        raise StableError(
            code=ErrorCode.INTERNAL,
            message=f"unknown error code on wire: {rpc.code!r}",
        )
    details: dict[str, Any] = {}
    if rpc.details_jcs:
        try:
            details = json.loads(bytes(rpc.details_jcs).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise StableError(
                code=ErrorCode.INTERNAL, message="unparseable error details"
            ) from exc
    return StableError(
        code=rpc.code,
        message=rpc.message_safe,
        details=details,
    )


def backend_error(exc: StableError) -> transport.RpcError:
    """Alias used by backend adapters for the common mapping direction."""

    return error_to_rpc(exc)


def negotiate_version(
    supported: Iterable[Any], *, server_major: int, server_minor: int
) -> tuple[int, int]:
    """Deterministic version selection for ``Negotiate`` (§41.41).

    Pick the highest common major; within it the selected minor is the
    largest minor the server supports that satisfies the client ranges
    (``min_minor <= selected <= max_minor``). Raises ``INVALID_ARGUMENT``
    when no range intersects.
    """

    ranges = list(supported)
    best: tuple[int, int] | None = None
    for rng in ranges:
        if rng.major != server_major:
            continue
        low = max(int(rng.min_minor), 0)
        high = int(rng.max_minor)
        if low > server_minor or high < low:
            continue
        candidate = min(server_minor, high)
        if candidate >= low and (best is None or candidate > best[1]):
            best = (server_major, candidate)
    if best is None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="no common protocol version",
            details={"server": f"{server_major}.{server_minor}"},
        )
    return best


def select_features(
    required: Iterable[str], optional: Iterable[str], available: dict[str, Any]
) -> tuple[set[str], set[str]]:
    """Feature negotiation for ``ClientHello`` (§41.27, §41.48.4).

    Returns ``(granted_required, granted_optional)``. A required feature the
    backend does not report ``SUPPORTED`` raises ``FEATURE_UNAVAILABLE`` —
    backends must never fake isolation/quota capabilities.
    """

    granted_required: set[str] = set()
    for feature in sorted(set(required)):
        if available.get(feature) != "SUPPORTED":
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message=f"required feature unavailable: {feature}",
                details={"feature": feature, "reported": str(available.get(feature))},
            )
        granted_required.add(feature)
    granted_optional = {f for f in set(optional) if available.get(f) == "SUPPORTED"}
    return granted_required, granted_optional
