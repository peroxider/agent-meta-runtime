"""Capability Health Probe v1 contract (§41.59.2).

Every required slot must declare a ``health_probe``; builtin probes are not
exempt. The descriptor is fixed: ``operation_id``, ``timeout_ms`` (1–10000,
default 5000), ``max_attempts`` (1–3, default 1), ``success_statuses`` (only
``READY`` allowed) and ``effect=PURE``. A probe may only return
``READY | DEGRADED | UNHEALTHY`` with a stable ``reason_code``; timeouts,
exceptions and schema errors all normalize to ``UNHEALTHY``. Retry intervals
are fixed at 1s then 2s reusing the same probe request id. Probes never write
Managed State and never produce network/filesystem/credential/external
effects (``effect=PURE``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import ErrorCode, StableError

__all__ = [
    "PROBE_STATUSES",
    "READY",
    "DEGRADED",
    "UNHEALTHY",
    "HealthProbeDescriptor",
    "ProbeResult",
    "normalize_probe_outcome",
]

READY = "READY"
DEGRADED = "DEGRADED"
UNHEALTHY = "UNHEALTHY"
PROBE_STATUSES = (READY, DEGRADED, UNHEALTHY)

#: Fixed retry intervals between attempts, reusing the same request id (§41.59.2).
PROBE_RETRY_DELAYS_S = (1.0, 2.0)


@dataclass(frozen=True, slots=True)
class HealthProbeDescriptor:
    """Fixed v1 probe descriptor parsed from a capability slot."""

    operation_id: str
    timeout_ms: int = 5000
    max_attempts: int = 1
    success_statuses: tuple[str, ...] = (READY,)

    def __post_init__(self) -> None:
        if not self.operation_id:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="health probe requires operation_id",
            )
        if not 1 <= self.timeout_ms <= 10_000:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="health probe timeout_ms must be within 1..10000",
                details={"timeout_ms": self.timeout_ms},
            )
        if not 1 <= self.max_attempts <= 3:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="health probe max_attempts must be within 1..3",
                details={"max_attempts": self.max_attempts},
            )
        if set(self.success_statuses) - {"READY"}:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="health probe success_statuses may only contain READY",
            )

    @classmethod
    def from_descriptor(cls, descriptor: Mapping[str, Any]) -> "HealthProbeDescriptor":
        """Parse the fixed descriptor fields; unknown shapes fail closed."""

        if not isinstance(descriptor, Mapping):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="health_probe must be a mapping"
            )
        return cls(
            operation_id=str(descriptor.get("operation_id", "")),
            timeout_ms=int(descriptor.get("timeout_ms", 5000)),
            max_attempts=int(descriptor.get("max_attempts", 1)),
            success_statuses=tuple(descriptor.get("success_statuses", ("READY",))),
        )


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Immutable probe observation (§41.59.2 response shape)."""

    status: str
    reason_code: str
    observed_at_us: int
    request_id: str
    slot: str
    attempt: int = 1


def normalize_probe_outcome(
    raw: Any, *, request_id: str, slot: str, attempt: int, observed_at_us: int
) -> ProbeResult:
    """Normalize any probe outcome into ``READY|DEGRADED|UNHEALTHY``.

    A mapping with a known status and reason becomes the result; anything
    else — exceptions, timeouts, schema violations, unknown statuses —
    collapses to ``UNHEALTHY`` with a stable reason code.
    """

    if isinstance(raw, Mapping) and set(raw) <= {"status", "reason_code"}:
        status = raw.get("status")
        reason_code = raw.get("reason_code")
        if status in PROBE_STATUSES and isinstance(reason_code, str):
            return ProbeResult(
                status=str(status),
                reason_code=reason_code,
                observed_at_us=observed_at_us,
                request_id=request_id,
                slot=slot,
                attempt=attempt,
            )
        reason = "PROBE_SCHEMA_ERROR"
    elif isinstance(raw, Mapping):
        reason = "PROBE_SCHEMA_ERROR"
    else:
        reason = "PROBE_INVALID_RESPONSE"
    return ProbeResult(
        status=UNHEALTHY,
        reason_code=reason,
        observed_at_us=observed_at_us,
        request_id=request_id,
        slot=slot,
        attempt=attempt,
    )
