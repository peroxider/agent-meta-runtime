"""Step 05 control-plane tests: probe execution (§41.59.2, §41.38 E)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.application.probes import (
    PROBE_REQUEST_FIELDS,
    ProbeRunner,
    probe_request_id,
)
from agent_meta_runtime.domain.errors import StableError
from agent_meta_runtime.domain.probe import HealthProbeDescriptor

RID = "rid-1234"
ALLOWED = set(PROBE_REQUEST_FIELDS)


def test_retry_ladder_reuses_one_request_id():
    descriptor = HealthProbeDescriptor(operation_id="probe.model", max_attempts=3)
    calls: list[dict] = []
    sleeps: list[float] = []

    def transport(request):
        calls.append(dict(request))
        if len(calls) < 3:
            raise TimeoutError("simulated timeout")
        return {"status": "READY", "reason_code": "OK"}

    report = ProbeRunner(
        transport=transport, sleep=sleeps.append, wall=lambda: 1_000_000.0
    ).run(descriptor, slot="model", criticality="REQUIRED", reconcile_id=RID)

    assert report.passed and report.result.status == "READY"
    assert report.attempts == 3
    assert sleeps == [1.0, 2.0]  # fixed ladder, no 4th delay
    assert len({c["request_id"] for c in calls}) == 1  # same probe request id
    assert calls[0]["request_id"] == probe_request_id(RID, "model", "probe.model")


def test_request_carries_only_identity_fields():
    seen: list[dict] = []

    def transport(request):
        seen.append(dict(request))
        return {"status": "READY", "reason_code": "OK"}

    ProbeRunner(transport=transport, sleep=lambda s: None, wall=lambda: 0.0).run(
        HealthProbeDescriptor(operation_id="op"),
        slot="s",
        criticality="REQUIRED",
        reconcile_id=RID,
        backend_session_id="session://x",
    )
    assert set(seen[0]) == ALLOWED  # never any credential values


def test_required_gate_rejects_degraded_and_unhealthy():
    descriptor = HealthProbeDescriptor(operation_id="op")

    degraded = ProbeRunner(
        transport=lambda r: {"status": "DEGRADED", "reason_code": "SLOW"},
        sleep=lambda s: None,
        wall=lambda: 0.0,
    ).run(descriptor, slot="s", criticality="REQUIRED", reconcile_id=RID)
    assert not degraded.passed and degraded.warning is None

    dead = ProbeRunner(
        transport=lambda r: {"status": "UNHEALTHY", "reason_code": "DOWN"},
        sleep=lambda s: None,
        wall=lambda: 0.0,
    ).run(descriptor, slot="s", criticality="REQUIRED", reconcile_id=RID)
    assert not dead.passed
    assert dead.fact_payload["new_status"] == "UNHEALTHY"


def test_preferred_slot_allows_degraded_with_warning_and_fact():
    descriptor = HealthProbeDescriptor(operation_id="op")
    report = ProbeRunner(
        transport=lambda r: {"status": "DEGRADED", "reason_code": "SLOW"},
        sleep=lambda s: None,
        wall=lambda: 0.0,
    ).run(descriptor, slot="cache", criticality="OPTIONAL", reconcile_id=RID)
    assert report.passed
    assert report.warning is not None
    assert report.warning.severity == "WARNING"
    assert report.warning.code == "PROBE_DEGRADED"
    assert report.fact_payload["new_status"] == "DEGRADED"
    assert report.fact_payload["reason_code"] == "SLOW"


def test_exception_and_garbage_normalize_to_unhealthy():
    descriptor = HealthProbeDescriptor(operation_id="op", max_attempts=1)

    def explode(request):
        raise ZeroDivisionError("boom")

    exploded = ProbeRunner(
        transport=explode, sleep=lambda s: None, wall=lambda: 0.0
    ).run(descriptor, slot="s", criticality="REQUIRED", reconcile_id=RID)
    assert not exploded.passed
    assert exploded.result.reason_code == "PROBE_TRANSPORT_ERROR"

    garbage = ProbeRunner(
        transport=lambda r: "nonsense", sleep=lambda s: None, wall=lambda: 0.0
    ).run(descriptor, slot="s", criticality="REQUIRED", reconcile_id=RID)
    assert garbage.result.status == "UNHEALTHY"
    assert garbage.result.reason_code == "PROBE_INVALID_RESPONSE"

    schema = ProbeRunner(
        transport=lambda r: {"status": "READY", "reason_code": 42, "extra": object()},
        sleep=lambda s: None,
        wall=lambda: 0.0,
    ).run(descriptor, slot="s", criticality="REQUIRED", reconcile_id=RID)
    assert schema.result.reason_code == "PROBE_SCHEMA_ERROR"


def test_descriptor_rejects_out_of_range_and_non_ready_success():
    with pytest.raises(StableError):
        HealthProbeDescriptor(operation_id="op", timeout_ms=0)
    with pytest.raises(StableError):
        HealthProbeDescriptor(operation_id="op", timeout_ms=10_001)
    with pytest.raises(StableError):
        HealthProbeDescriptor(operation_id="op", max_attempts=4)
    with pytest.raises(StableError):
        HealthProbeDescriptor(operation_id="op", success_statuses=("READY", "OK"))


def test_stable_probe_request_id_is_pure_function():
    assert probe_request_id(RID, "s", "op") == probe_request_id(RID, "s", "op")
    assert probe_request_id(RID, "s", "op") != probe_request_id(RID, "s2", "op")
    assert probe_request_id(RID, "s", "op") != probe_request_id("rid-2", "s", "op")
