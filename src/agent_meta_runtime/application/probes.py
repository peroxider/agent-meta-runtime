"""Health probe execution (§41.59.2, §41.38 step E).

The runner executes a fixed ``HealthProbeDescriptor`` against a pluggable
transport and normalizes every outcome through ``normalize_probe_outcome``.
Attempts reuse one stable probe request id derived from the reconcile id,
slot and operation; retry intervals are the fixed 1s/2s ladder and only
``UNHEALTHY`` outcomes are retried — ``READY``/``DEGRADED`` are definitive
observations. The required-slot gate passes only on ``READY``; a preferred
slot additionally passes on ``DEGRADED`` while emitting a WARNING issue and
an ``instance_degraded`` fact payload for the Reconciler to append inside its
own transaction. Probe requests carry only the fixed identity fields below —
never Root/Provider credential values — and are routed pre-serving so probe
traffic can never reach the serving composition.
"""

from __future__ import annotations

import hashlib
import asyncio
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..domain.compatibility import CompatibilityIssue
from ..domain.probe import (
    DEGRADED,
    PROBE_RETRY_DELAYS_S,
    READY,
    UNHEALTHY,
    HealthProbeDescriptor,
    normalize_probe_outcome,
)
from ..domain.probe import ProbeResult
from .steps import Call, drive, drive_async

__all__ = [
    "PROBE_REQUEST_FIELDS",
    "ProbeTransport",
    "ProbeReport",
    "ProbeRunner",
    "probe_request_id",
]

Transport = Callable[[Mapping[str, Any]], Any]
"""transport(request) performs the probe call and returns any raw outcome;
exceptions (including timeouts) are normalized to ``UNHEALTHY``."""

PROBE_REQUEST_FIELDS = (
    "request_id",
    "reconcile_id",
    "composition_id",
    "slot",
    "instance_id",
    "descriptor_revision",
    "backend_session_id",
    "operation_id",
    "timeout_ms",
)


def probe_request_id(reconcile_id: str, slot: str, operation_id: str) -> str:
    """Stable probe request id, identical across all attempts of one probe."""

    preimage = b"\x00".join(
        part.encode("utf-8")
        for part in ("probe", reconcile_id, slot, operation_id)
    )
    return hashlib.sha256(preimage).hexdigest()


@dataclass(frozen=True, slots=True)
class ProbeReport:
    """Final probe observation plus its gate decision (§41.38 step E)."""

    slot: str
    criticality: str
    result: ProbeResult
    attempts: int
    passed: bool
    warning: CompatibilityIssue | None = None
    fact_payload: Mapping[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "criticality": self.criticality,
            "status": self.result.status,
            "reason_code": self.result.reason_code,
            "attempts": self.attempts,
            "passed": self.passed,
            "request_id": self.result.request_id,
            "observed_at_us": self.result.observed_at_us,
        }


class ProbeRunner:
    """Executes probes with the fixed retry ladder and slot gate."""

    def __init__(
        self,
        *,
        transport: Transport,
        sleep: Callable[[float], None] = time.sleep,
        wall: Callable[[], float] = time.time,
        async_sleep: Callable = asyncio.sleep,
    ) -> None:
        self._transport = transport
        self._sleep = sleep
        self._wall = wall
        self._async_sleep = async_sleep

    def _execute_steps(self, request: dict[str, Any], attempt: int):
        try:
            raw = yield Call(self._transport, (request,), timeout_s=request["timeout_ms"] / 1000)
        except TimeoutError:
            raw = {"status": UNHEALTHY, "reason_code": "PROBE_TIMEOUT"}
        except Exception:
            raw = {"status": UNHEALTHY, "reason_code": "PROBE_TRANSPORT_ERROR"}
        return normalize_probe_outcome(
            raw,
            request_id=request["request_id"],
            slot=request["slot"],
            attempt=attempt,
            observed_at_us=int(self._wall() * 1_000_000),
        )

    def _probe_steps(
        self,
        descriptor: HealthProbeDescriptor,
        *,
        slot: str,
        criticality: str,
        reconcile_id: str,
        composition_id: str = "",
        instance_id: str = "",
        descriptor_revision: int = 0,
        backend_session_id: str = "",
        async_wait: bool = False,
    ):
        """Probe one slot; returns the gate decision for the Reconciler."""

        if criticality not in ("REQUIRED", "OPTIONAL"):
            raise ValueError(f"unknown slot criticality: {criticality!r}")
        request_id = probe_request_id(reconcile_id, slot, descriptor.operation_id)
        result: ProbeResult | None = None
        attempts = 0
        for attempt in range(1, descriptor.max_attempts + 1):
            attempts = attempt
            request: dict[str, Any] = {
                "request_id": request_id,
                "reconcile_id": reconcile_id,
                "composition_id": composition_id,
                "slot": slot,
                "instance_id": instance_id,
                "descriptor_revision": descriptor_revision,
                "backend_session_id": backend_session_id,
                "operation_id": descriptor.operation_id,
                "timeout_ms": descriptor.timeout_ms,
            }
            assert set(request) == set(PROBE_REQUEST_FIELDS)
            outcome = yield from self._execute_steps(request, attempt)
            result = ProbeResult(
                status=outcome.status,
                reason_code=outcome.reason_code,
                observed_at_us=outcome.observed_at_us,
                request_id=request_id,
                slot=slot,
                attempt=attempt,
            )
            if result.status != UNHEALTHY:
                break
            if attempt < descriptor.max_attempts:
                yield Call(self._async_sleep if async_wait else self._sleep, (
                    PROBE_RETRY_DELAYS_S[min(attempt - 1, len(PROBE_RETRY_DELAYS_S) - 1)],
                ))
        assert result is not None

        warning: CompatibilityIssue | None = None
        fact_payload: dict[str, Any] | None = None
        if criticality == "REQUIRED":
            passed = result.status == READY
        else:
            passed = result.status in (READY, DEGRADED)
        if result.status == DEGRADED and criticality == "OPTIONAL":
            # preferred degradation keeps the gate green but records a WARNING;
            # for required slots the degraded outcome is carried by the fact.
            warning = CompatibilityIssue(
                code="PROBE_DEGRADED",
                severity="WARNING",
                path=f"/slots/{slot}",
                message_template_id="probe.degraded",
            )
        if result.status in (DEGRADED, UNHEALTHY):
            fact_payload = {
                "reason_code": result.reason_code,
                "old_status": "READY",
                "new_status": result.status,
                "slot": slot,
                "reconcile_id": reconcile_id,
                "request_id": request_id,
                "attempt": str(result.attempt),
            }
        return ProbeReport(
            slot=slot,
            criticality=criticality,
            result=result,
            attempts=attempts,
            passed=passed,
            warning=warning,
            fact_payload=fact_payload,
        )

    def run(self, descriptor: HealthProbeDescriptor, **kwargs) -> ProbeReport:
        return drive(self._probe_steps(descriptor, **kwargs))

    async def run_async(self, descriptor: HealthProbeDescriptor, **kwargs) -> ProbeReport:
        return await drive_async(self._probe_steps(descriptor, async_wait=True, **kwargs))
