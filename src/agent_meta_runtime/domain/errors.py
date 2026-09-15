"""Stable error code registry and result types (§41.14, §41.42.3).

Error codes are part of the frozen public contract. Codes are uppercase ASCII
tokens; retryability is fixed per code and must drive retry policy together
with operation idempotency and effect reversibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json

__all__ = [
    "ErrorCode",
    "StableError",
    "RETRYABLE_CODES",
    "error_from_json",
]


class ErrorCode:
    """Namespace of stable error codes with fixed retry semantics."""

    # §41.14
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    AUTHORITY_DENIED = "AUTHORITY_DENIED"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    FEATURE_UNAVAILABLE = "FEATURE_UNAVAILABLE"
    NO_SERVING_COMPOSITION = "NO_SERVING_COMPOSITION"
    SERVING_NOT_READY = "SERVING_NOT_READY"
    CONTRACT_INCOMPATIBLE = "CONTRACT_INCOMPATIBLE"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    HANDLE_EXPIRED = "HANDLE_EXPIRED"
    EXTERNAL_EFFECT_UNKNOWN = "EXTERNAL_EFFECT_UNKNOWN"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"
    # §41.42.3
    INVALID_RESULT = "INVALID_RESULT"
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    ALREADY_RUNNING = "ALREADY_RUNNING"
    FAILED_PRECONDITION = "FAILED_PRECONDITION"
    COMPATIBILITY_UNKNOWN = "COMPATIBILITY_UNKNOWN"
    KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
    DATA_LOSS = "DATA_LOSS"
    INTERNAL = "INTERNAL"

    ALL: frozenset[str] = frozenset(
        {
            INVALID_ARGUMENT,
            AUTHORITY_DENIED,
            REVISION_CONFLICT,
            IDEMPOTENCY_CONFLICT,
            FEATURE_UNAVAILABLE,
            NO_SERVING_COMPOSITION,
            SERVING_NOT_READY,
            CONTRACT_INCOMPATIBLE,
            RESOURCE_EXHAUSTED,
            DEADLINE_EXCEEDED,
            BACKEND_UNAVAILABLE,
            HANDLE_EXPIRED,
            EXTERNAL_EFFECT_UNKNOWN,
            INTEGRITY_ERROR,
            INVALID_RESULT,
            NOT_FOUND,
            ALREADY_EXISTS,
            ALREADY_RUNNING,
            FAILED_PRECONDITION,
            COMPATIBILITY_UNKNOWN,
            KEY_UNAVAILABLE,
            DATA_LOSS,
            INTERNAL,
        }
    )


# ``None`` means "depends on the operation" (idempotency / reversibility).
RETRYABLE_CODES: dict[str, bool | None] = {
    ErrorCode.INVALID_ARGUMENT: False,
    ErrorCode.AUTHORITY_DENIED: False,
    ErrorCode.REVISION_CONFLICT: None,  # retry after re-reading current state
    ErrorCode.IDEMPOTENCY_CONFLICT: False,
    ErrorCode.FEATURE_UNAVAILABLE: None,  # per composition on_missing policy
    ErrorCode.NO_SERVING_COMPOSITION: False,
    ErrorCode.SERVING_NOT_READY: True,
    ErrorCode.CONTRACT_INCOMPATIBLE: False,
    ErrorCode.RESOURCE_EXHAUSTED: True,
    ErrorCode.DEADLINE_EXCEEDED: None,  # depends on effect outcome
    ErrorCode.BACKEND_UNAVAILABLE: True,
    ErrorCode.HANDLE_EXPIRED: None,  # after reconcile
    ErrorCode.EXTERNAL_EFFECT_UNKNOWN: None,  # never auto-retry non-idempotent
    ErrorCode.INTEGRITY_ERROR: False,
    ErrorCode.INVALID_RESULT: False,
    ErrorCode.NOT_FOUND: False,
    ErrorCode.ALREADY_EXISTS: False,
    ErrorCode.ALREADY_RUNNING: False,
    ErrorCode.FAILED_PRECONDITION: None,  # after repair
    ErrorCode.COMPATIBILITY_UNKNOWN: False,
    ErrorCode.KEY_UNAVAILABLE: None,  # after key recovery
    ErrorCode.DATA_LOSS: False,
    ErrorCode.INTERNAL: None,  # depends on details
}


@dataclass(frozen=True, slots=True)
class StableError(Exception):
    """A stable, serializable error carrying a registry code."""

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in ErrorCode.ALL:
            raise ValueError(f"unknown error code: {self.code!r}")

    @property
    def retryable(self) -> bool | None:
        return RETRYABLE_CODES[self.code]

    def to_json(self) -> dict[str, Any]:
        """Redacted JSON mapping; never includes secrets or raw payloads."""

        return {
            "code": self.code,
            "retryable": self.retryable,
            "message": self.message,
            "details": self.details,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_json())

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.code}: {self.message}"


def error_from_json(data: dict[str, Any]) -> StableError:
    code = data.get("code")
    if code not in ErrorCode.ALL:
        raise ValueError(f"unknown error code in payload: {code!r}")
    return StableError(
        code=code,
        message=str(data.get("message", "")),
        details=dict(data.get("details", {})),
    )
