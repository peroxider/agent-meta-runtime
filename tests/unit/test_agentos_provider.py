"""AgentOSProvider contract gate (docs/plans/agentos-execution-kernel-bridge.md).

The bridge runs against an in-process fake kernel speaking the real frozen
``agentos.kernel.v1`` message shapes, so the same eight-RPC session
assertions that gate the FakeProvider (test_agentos_client.py) also gate the
production translation layer — without a live ``agentos-kerneld``. The
daemon-backed smoke is separate external evidence (see
tests/integration/test_agentos_kerneld_smoke.py).
"""

from __future__ import annotations

import json
import time
import uuid as uuid_module
from pathlib import Path
from typing import Any

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.execution_agentos import AgentOSProvider
from agent_meta_runtime.adapters.execution_agentos.kernel_transport import KernelRpcError
from agent_meta_runtime.adapters.execution_agentos.mapping import (
    activity_name,
    realm_name,
)
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport
from agent_meta_runtime.protocols._kernel_v1 import common_pb2 as kcommon
from agent_meta_runtime.protocols._kernel_v1 import control_pb2 as kcontrol
from agent_meta_runtime.protocols._kernel_v1 import service_pb2 as kservice
from agent_meta_runtime.protocols._kernel_v1 import types_pb2 as ktypes
from agent_meta_runtime.protocols.backend_wire import (
    build_envelope,
    new_request_id,
    payload_hash,
)

_REQUEST_TYPES: dict[str, Any] = {
    "Hello": kservice.HelloRequest,
    "GetKernelStatus": kservice.GetKernelStatusRequest,
    "CreateRealm": kservice.CreateRealmRequest,
    "InspectRealm": kservice.InspectRealmRequest,
    "SpawnProcess": kservice.SpawnProcessRequest,
    "InspectProcess": kservice.InspectProcessRequest,
    "SubmitActivity": kservice.SubmitActivityRequest,
    "InspectActivity": kservice.InspectActivityRequest,
    "WaitActivity": kservice.WaitActivityRequest,
    "CancelActivity": kservice.CancelActivityRequest,
    "KillProcess": kservice.KillProcessRequest,
    "GetSnapshot": kservice.GetSnapshotRequest,
}


class FakeKernelTransport:
    """In-process kernel semantics over the KernelTransport seam.

    Implements exactly the RPC subset the bridge uses, with honest state
    machine behavior: deterministic ALREADY_EXISTS/NOT_FOUND/STALE_GENERATION
    errors, wait deadlines, the cancel ladder, and process kill. ``runner``
    decides what a submitted activity does (default: echo-complete). Tests
    drive progress via :meth:`complete_activity` / :meth:`drop_activity`.
    """

    def __init__(
        self,
        *,
        kernel_instance_id: str = "kernel-test-0001",
        runner: Any = None,
        enabled_features: tuple[str, ...] = ("k1.realm", "k1.activity"),
        poll_interval_s: float = 0.005,
    ) -> None:
        self.kernel_instance_id = kernel_instance_id
        self.enabled_features = list(enabled_features)
        self._clock = lambda: time.time_ns() // 1000  # noqa: E731
        self._runner = runner
        self._poll_interval_s = poll_interval_s
        self._realms: dict[str, kcontrol.RealmRecord] = {}
        self._processes: dict[str, kcontrol.ProcessRecord] = {}
        self._activities: dict[str, kcontrol.ActivityRecord] = {}
        self.calls: list[tuple[str, Any]] = []
        self.cancel_completes = True

    # -- test driving helpers ------------------------------------------------
    def complete_activity(
        self,
        name: str,
        *,
        state: int = ktypes.ACTIVITY_STATE_COMPLETED,
        payload: bytes = b"",
        error: kcommon.KernelError | None = None,
        exit_code: int | None = None,
    ) -> None:
        record = self._activities[name]
        result = record.result
        result.terminal_state = state
        result.completion_kind = ktypes.COMPLETION_KIND_PROCESS_EXIT
        result.completed_at.FromMicroseconds(self._clock())
        if payload:
            result.payload.data = payload
        if error is not None:
            result.error.CopyFrom(error)
        if exit_code is not None:
            result.exit_code = exit_code
        result.usage.cpu_nanos = 1_000
        result.usage.memory_peak_bytes = 2_048
        record.state = state
        record.updated_at.FromMicroseconds(self._clock())

    def drop_activity(self, name: str) -> None:
        del self._activities[name]

    def restart_kernel(self) -> None:
        """Simulate kernel restart recovery: generations advance."""

        for record in self._activities.values():
            record.ref.generation += 1
            record.ref.revision += 1
            if not terminal(record.state):
                record.state = ktypes.ACTIVITY_STATE_READY

    # -- transport seam --------------------------------------------------------
    async def call(self, method: str, request: bytes) -> bytes:
        if method not in _REQUEST_TYPES:
            raise StableError(
                code=ErrorCode.BACKEND_UNAVAILABLE,
                message=f"fake kernel: unknown method {method}",
            )
        message = _REQUEST_TYPES[method]()
        message.ParseFromString(request)
        self.calls.append((method, message))
        response = getattr(self, "_" + method)(message)
        return response.SerializeToString()

    def close(self) -> None:  # pragma: no cover - seam parity
        pass

    def _meta(self, req: Any) -> kcommon.ResponseMeta:
        meta = kcommon.ResponseMeta(
            request_id=req.meta.request_id,
            kernel_instance_id=self.kernel_instance_id,
            kernel_revision=1,
        )
        meta.server_time.FromMicroseconds(self._clock())
        return meta

    def _fail(self, code: int, message: str) -> KernelRpcError:
        return KernelRpcError(code, message)

    # -- RPC handlers ------------------------------------------------------------
    def _Hello(self, req: kservice.HelloRequest) -> kservice.HelloResponse:
        return kservice.HelloResponse(
            selected_abi_version="v1",
            enabled_features=self.enabled_features,
            kernel_instance_id=self.kernel_instance_id,
            server_version="fake-kernel-1.0",
        )

    def _GetKernelStatus(
        self, req: kservice.GetKernelStatusRequest
    ) -> kservice.GetKernelStatusResponse:
        status = kcontrol.KernelStatus(
            state=ktypes.KERNEL_STATE_READY,
            kernel_instance_id=self.kernel_instance_id,
            server_version="fake-kernel-1.0",
            schema_version=1,
            global_revision=1,
        )
        status.enabled_features.extend(self.enabled_features)
        response = kservice.GetKernelStatusResponse(status=status)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _CreateRealm(self, req: kservice.CreateRealmRequest) -> kservice.CreateRealmResponse:
        name = req.spec.requested_name
        if name in self._realms:
            raise self._fail(kcommon.ALREADY_EXISTS, f"realm {name} exists")
        record = kcontrol.RealmRecord(
            adapter_kind=req.spec.adapter_kind,
            isolation_level=req.spec.minimum_isolation,
            state=ktypes.REALM_STATE_READY,
        )
        record.ref.name = name
        record.ref.generation = 1
        record.ref.revision = 1
        self._realms[name] = record
        response = kservice.CreateRealmResponse(realm=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _InspectRealm(self, req: kservice.InspectRealmRequest) -> kservice.InspectRealmResponse:
        record = self._realms.get(req.realm_name)
        if record is None:
            raise self._fail(kcommon.NOT_FOUND, f"realm {req.realm_name} unknown")
        response = kservice.InspectRealmResponse(realm=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _SpawnProcess(self, req: kservice.SpawnProcessRequest) -> kservice.SpawnProcessResponse:
        name = req.spec.requested_name
        if req.spec.realm_name not in self._realms:
            raise self._fail(kcommon.NOT_FOUND, f"realm {req.spec.realm_name} unknown")
        if name in self._processes:
            raise self._fail(kcommon.ALREADY_EXISTS, f"process {name} exists")
        record = kcontrol.ProcessRecord(
            realm_name=req.spec.realm_name, state=ktypes.PROCESS_STATE_RUNNING
        )
        record.ref.name = name
        record.ref.generation = 1
        record.ref.revision = 1
        self._processes[name] = record
        response = kservice.SpawnProcessResponse(process=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _InspectProcess(
        self, req: kservice.InspectProcessRequest
    ) -> kservice.InspectProcessResponse:
        record = self._processes.get(req.process_name)
        if record is None:
            raise self._fail(kcommon.NOT_FOUND, f"process {req.process_name} unknown")
        response = kservice.InspectProcessResponse(process=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _SubmitActivity(
        self, req: kservice.SubmitActivityRequest
    ) -> kservice.SubmitActivityResponse:
        spec = req.spec
        if spec.requested_name in self._activities:
            raise self._fail(
                kcommon.ALREADY_EXISTS, f"activity {spec.requested_name} exists"
            )
        if spec.process_name not in self._processes:
            raise self._fail(kcommon.NOT_FOUND, f"process {spec.process_name} unknown")
        record = kcontrol.ActivityRecord(
            process_name=spec.process_name,
            realm_name=spec.realm_name,
            state=ktypes.ACTIVITY_STATE_RUNNING,
        )
        record.ref.name = spec.requested_name
        record.ref.generation = 1
        record.ref.revision = 1
        record.hard_deadline.CopyFrom(spec.hard_deadline)
        now = self._clock()
        record.created_at.FromMicroseconds(now)
        record.updated_at.FromMicroseconds(now)
        self._activities[spec.requested_name] = record
        outcome = (
            self._runner(record, spec) if self._runner is not None else _echo_result(spec)
        )
        if outcome is not None:
            record.result.CopyFrom(outcome)
            record.state = outcome.terminal_state
        response = kservice.SubmitActivityResponse(activity=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _InspectActivity(
        self, req: kservice.InspectActivityRequest
    ) -> kservice.InspectActivityResponse:
        record = self._activities.get(req.activity_name)
        if record is None:
            raise self._fail(
                kcommon.NOT_FOUND, f"activity {req.activity_name} unknown"
            )
        response = kservice.InspectActivityResponse(activity=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _WaitActivity(self, req: kservice.WaitActivityRequest) -> kservice.WaitActivityResponse:
        record = self._activities.get(req.activity_name)
        if record is None:
            raise self._fail(
                kcommon.NOT_FOUND, f"activity {req.activity_name} unknown"
            )
        if record.ref.generation != req.expected_generation:
            raise self._fail(
                kcommon.STALE_GENERATION,
                f"activity {req.activity_name} is at generation {record.ref.generation}",
            )
        deadline_us = (
            req.meta.deadline.seconds * 1_000_000 + req.meta.deadline.nanos // 1000
            if req.meta.HasField("deadline")
            else 0
        )
        while not terminal(record.state):
            if deadline_us and self._clock() >= deadline_us:
                raise self._fail(
                    kcommon.DEADLINE_EXCEEDED,
                    f"activity {req.activity_name} not terminal before deadline",
                )
            time.sleep(self._poll_interval_s)
        response = kservice.WaitActivityResponse(activity=record)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _CancelActivity(
        self, req: kservice.CancelActivityRequest
    ) -> kservice.OperationResponse:
        record = self._activities.get(req.activity_name)
        if record is None:
            raise self._fail(
                kcommon.NOT_FOUND, f"activity {req.activity_name} unknown"
            )
        if (
            record.ref.generation != req.expected_generation
            or record.ref.revision != req.expected_revision
        ):
            raise self._fail(
                kcommon.STALE_GENERATION,
                f"activity {req.activity_name} moved on",
            )
        if not terminal(record.state):
            if self.cancel_completes:
                self.complete_activity(
                    req.activity_name, state=ktypes.ACTIVITY_STATE_CANCELLED
                )
            else:
                record.state = ktypes.ACTIVITY_STATE_CANCELLING
        response = kservice.OperationResponse(operation=self._operation(req, "activity.cancel"))
        response.meta.CopyFrom(self._meta(req))
        return response

    def _KillProcess(self, req: kservice.KillProcessRequest) -> kservice.OperationResponse:
        if req.process_name not in self._processes:
            raise self._fail(kcommon.NOT_FOUND, f"process {req.process_name} unknown")
        for record in self._activities.values():
            if record.process_name == req.process_name and not terminal(record.state):
                self.complete_activity(
                    record.ref.name, state=ktypes.ACTIVITY_STATE_KILLED
                )
        process = self._processes[req.process_name]
        process.state = ktypes.PROCESS_STATE_KILLING
        response = kservice.OperationResponse(
            operation=self._operation(req, "process.kill")
        )
        response.meta.CopyFrom(self._meta(req))
        return response

    def _GetSnapshot(self, req: kservice.GetSnapshotRequest) -> kservice.GetSnapshotResponse:
        names = sorted(self._activities)
        start = int(req.page_token) if req.page_token else 0
        page = names[start : start + req.page_size]
        snapshot = kservice.Snapshot()
        for name in page:
            snapshot.activities.add().CopyFrom(self._activities[name])
        response = kservice.GetSnapshotResponse(snapshot=snapshot)
        if start + req.page_size < len(names):
            response.next_page_token = str(start + req.page_size)
        response.meta.CopyFrom(self._meta(req))
        return response

    def _operation(self, req: Any, kind: str) -> kcontrol.OperationRecord:
        record = kcontrol.OperationRecord(kind=kind, request_id=req.meta.request_id)
        record.ref.name = f"op-{len(self.calls)}"
        record.ref.generation = 1
        record.ref.revision = 1
        return record


def terminal(state: int) -> bool:
    return state in (
        ktypes.ACTIVITY_STATE_COMPLETED,
        ktypes.ACTIVITY_STATE_FAILED,
        ktypes.ACTIVITY_STATE_CANCELLED,
        ktypes.ACTIVITY_STATE_TIMED_OUT,
        ktypes.ACTIVITY_STATE_KILLED,
    )


def _echo_result(spec: kcontrol.ActivitySpec) -> kcontrol.ActivityResult:
    result = kcontrol.ActivityResult(terminal_state=ktypes.ACTIVITY_STATE_COMPLETED)
    result.completion_kind = ktypes.COMPLETION_KIND_PROCESS_EXIT
    result.payload.data = spec.payload.data
    result.exit_code = 0
    result.usage.cpu_nanos = 1_000
    result.usage.memory_peak_bytes = 2_048
    return result


# -- gate helpers -------------------------------------------------------------------

def make_hello(*required: str, optional: tuple[str, ...] = ()) -> eb.ClientHello:
    hello = eb.ClientHello(
        client_instance_id="gate-runner",
        required_features=list(required),
        optional_features=list(optional),
    )
    hello.supported.add(major=1, min_minor=0, max_minor=0)
    return hello


def make_request(rid: str, kind: str, payload: bytes) -> eb.ExecutionRequest:
    return eb.ExecutionRequest(
        session_id="sess",
        realm_id="realm://main",
        request_id=rid,
        operation_kind=kind,
        payload_hash=payload_hash(payload),
        payload_jcs=payload,
        idempotency_class="KEYED",
        reversibility="REVERSIBLE",
        dedupe_scope="task",
        requested_retention_us=3_600_000_000,
    )


def make_provider(tmp_path: Path, kernel: FakeKernelTransport, **kw: Any) -> AgentOSProvider:
    return AgentOSProvider(Path(tmp_path) / "data", transport=kernel, **kw)


async def framed(provider: AgentOSProvider, name: str, message: Any, **kw: Any) -> Any:
    """Drive the provider through the framed envelope contract."""

    method = f"agent_meta.execution_backend.v1.Backend.{name}"
    envelope = build_envelope(
        method=method,
        payload=message.SerializeToString(),
        request_id=new_request_id(),
        **kw,
    )
    response = transport.RpcEnvelope()
    response.ParseFromString(await provider.dispatch(envelope.SerializeToString()))
    assert response.is_response
    if response.HasField("error"):
        details = json.loads(bytes(response.error.details_jcs) or b"{}")
        raise StableError(
            code=response.error.code, message=response.error.message_safe, details=details
        )
    return response.payload


# -- tests -----------------------------------------------------------------------------


async def test_negotiate_reports_managed_session(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    session = await provider.negotiate(make_hello())
    assert session.profile == "MANAGED"
    assert session.protocol_major == 1
    assert session.backend_id == "backend://agentos-kernel/kernel-test-0001"
    assert json.loads(bytes(session.features_jcs)) == []
    limits = json.loads(bytes(session.limits_jcs))
    assert limits["kernel_state"] == "KERNEL_STATE_READY"
    assert session.established_at_us > 0


async def test_negotiate_rejects_unsupported_major(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    hello = eb.ClientHello()
    hello.supported.add(major=2, min_minor=0, max_minor=0)
    with pytest.raises(StableError) as excinfo:
        await provider.negotiate(hello)
    assert excinfo.value.code == ErrorCode.CONTRACT_INCOMPATIBLE


async def test_required_feature_missing_is_contract_incompatible(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    with pytest.raises(StableError) as excinfo:
        await provider.negotiate(make_hello("network_isolation"))
    assert excinfo.value.code == ErrorCode.CONTRACT_INCOMPATIBLE


async def test_submit_await_inspect_roundtrip(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    payload = canonical_json({"kind": "echo", "value": 42})
    rid = new_request_id()
    handle = await provider.submit(make_request(rid, "test.echo", payload))
    assert handle.request_id == rid
    assert handle.incarnation == 1
    assert handle.backend_id.startswith("backend://agentos-kernel/")
    # Deterministic derivation: realm/process names never leak the raw id.
    decoded = json.loads(bytes(handle.opaque_handle))
    assert decoded["name"] == activity_name(rid)
    assert kernel._realms[realm_name("realm://main")].ref.name == realm_name("realm://main")

    result = await provider.await_activity(handle, 0)
    assert result.status == "COMPLETED"
    assert result.request_id == rid
    assert result.result_hash == sha256_hex(payload)
    assert result.result_artifact_id.endswith(result.result_hash)
    assert result.effect_state_unknown is False
    usage = json.loads(bytes(result.usage_jcs))
    assert usage["memory_peak_bytes"] == 2048
    assert usage["exit_code"] == 0

    snapshot = await provider.inspect(handle)
    assert snapshot.status == "COMPLETED"
    assert snapshot.handle.request_id == rid
    assert snapshot.terminal.status == "COMPLETED"
    # The payload landed in the bridge CAS under its own hash.
    blob = FilesystemCas(Path(tmp_path) / "data").open_blob(
        result.result_artifact_id, result.result_hash, len(payload)
    )
    assert blob == payload


async def test_submit_idempotent_replay_and_conflict(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    await provider.negotiate(make_hello())
    payload = canonical_json({"kind": "echo"})
    rid = new_request_id()
    first = await provider.submit(make_request(rid, "test.echo", payload))
    replay = await provider.submit(make_request(rid, "test.echo", payload))
    assert bytes(replay.opaque_handle) == bytes(first.opaque_handle)
    with pytest.raises(StableError) as excinfo:
        await provider.submit(
            make_request(rid, "test.echo", canonical_json({"kind": "other"}))
        )
    assert excinfo.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


async def test_submit_replay_after_kernel_restart_finds_activity(tmp_path) -> None:
    # Crash between ledger commit and kernel visibility: the replay path
    # re-submits when the kernel has no record (§2.2 idempotency).
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    payload = canonical_json({"kind": "echo"})
    rid = new_request_id()
    handle = await provider.submit(make_request(rid, "test.echo", payload))
    kernel.drop_activity(f"act-{rid}")
    replay = await provider.submit(make_request(rid, "test.echo", payload))
    assert bytes(replay.opaque_handle) == bytes(handle.opaque_handle)


async def test_await_deadline_returns_running(tmp_path) -> None:
    kernel = FakeKernelTransport(runner=lambda record, spec: None)
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    handle = await provider.submit(
        make_request(new_request_id(), "test.echo", canonical_json({"kind": "hang"}))
    )
    past = time.time_ns() // 1000 - 1_000_000
    result = await provider.await_activity(handle, past)
    assert result.status == "RUNNING"
    assert result.effect_state_unknown is False
    assert result.result_hash == ""


async def test_stale_generation_maps_to_handle_expired(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    handle = await provider.submit(
        make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    )
    stale = eb.ExecutionHandle()
    stale.CopyFrom(handle)
    stale.incarnation = stale.incarnation + 1
    decoded = json.loads(bytes(stale.opaque_handle))
    decoded["generation"] += 1
    stale.opaque_handle = canonical_json(decoded)
    with pytest.raises(StableError) as excinfo:
        await provider.await_activity(stale, 0)
    assert excinfo.value.code == ErrorCode.HANDLE_EXPIRED


async def test_cancel_graceful_confirms_terminal(tmp_path) -> None:
    kernel = FakeKernelTransport(runner=lambda record, spec: None)
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    handle = await provider.submit(
        make_request(new_request_id(), "test.echo", canonical_json({"kind": "hang"}))
    )
    request = eb.CancelRequest(handle=handle, mode="GRACEFUL")
    report = await provider.cancel(request)
    assert report.terminal_confirmed is True
    assert report.status == "CANCELLED"
    result = await provider.await_activity(handle, 0)
    assert result.status == "CANCELLED"


async def test_cancel_kill_mode_upgrades_to_kill_process(tmp_path) -> None:
    kernel = FakeKernelTransport(runner=lambda record, spec: None)
    kernel.cancel_completes = False
    provider = make_provider(tmp_path, kernel, poll_interval_s=0.0)
    await provider.negotiate(make_hello())
    rid = new_request_id()
    handle = await provider.submit(
        make_request(rid, "test.echo", canonical_json({"kind": "hang"}))
    )
    deadline = time.time_ns() // 1000 + 300_000
    report = await provider.cancel(
        eb.CancelRequest(handle=handle, mode="KILL", deadline_at_us=deadline)
    )
    assert any(method == "KillProcess" for method, _ in kernel.calls)
    assert report.terminal_confirmed is True
    # KILLED maps to FAILED with a killed marker in error_jcs (§1.1).
    assert report.status == "FAILED"
    result = await provider.await_activity(handle, 0)
    assert result.status == "FAILED"
    error = json.loads(bytes(result.error_jcs))
    assert error["kernel_code"] == "ACTIVITY_STATE_KILLED"


async def test_cancel_rejects_unknown_mode(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    await provider.negotiate(make_hello())
    handle = await provider.submit(
        make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    )
    with pytest.raises(StableError) as excinfo:
        await provider.cancel(eb.CancelRequest(handle=handle, mode="NUKE"))
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


async def test_reconcile_terminal_binding_and_orphan(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    payload = canonical_json({"kind": "echo"})
    rid = new_request_id()
    handle = await provider.submit(make_request(rid, "test.echo", payload))
    lost_rid = new_request_id()
    lost_handle = await provider.submit(
        make_request(lost_rid, "test.echo", canonical_json({"kind": "lost"}))
    )
    kernel.drop_activity(f"act-{lost_rid}")
    request = eb.ReconcileRequest(
        session_id="sess",
        realm_id="realm://main",
        known=[
            eb.KnownBinding(
                semantic_id="a",
                request_id=rid,
                handle=handle,
                payload_hash=payload_hash(payload),
            ),
            eb.KnownBinding(
                semantic_id="b",
                request_id=lost_rid,
                handle=lost_handle,
                payload_hash=payload_hash(canonical_json({"kind": "lost"})),
            ),
        ],
    )
    report = await provider.reconcile(request)
    assert len(report.bindings) == 1
    assert report.bindings[0].known.request_id == rid
    assert report.bindings[0].status == "TERMINAL"
    assert report.bindings[0].terminal.result_hash == sha256_hex(payload)
    assert len(report.orphans) == 1
    assert report.orphans[0].request_id == lost_rid
    assert report.orphans[0].recommended_action == "resubmit"
    assert report.observed_at_us > 0


async def test_reconcile_renews_generation_after_kernel_restart(tmp_path) -> None:
    kernel = FakeKernelTransport(runner=lambda record, spec: None)
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    rid = new_request_id()
    handle = await provider.submit(
        make_request(rid, "test.echo", canonical_json({"kind": "hang"}))
    )
    kernel.restart_kernel()
    report = await provider.reconcile(
        eb.ReconcileRequest(
            session_id="sess",
            realm_id="realm://main",
            known=[eb.KnownBinding(request_id=rid, handle=handle)],
        )
    )
    renewed = report.bindings[0].renewed_handle
    assert renewed.incarnation == handle.incarnation + 1
    assert report.bindings[0].status == "RUNNING"


async def test_reconcile_integrity_error_on_hash_divergence(tmp_path) -> None:
    kernel = FakeKernelTransport(runner=lambda record, spec: None)
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    rid = new_request_id()
    handle = await provider.submit(
        make_request(rid, "test.echo", canonical_json({"kind": "hang"}))
    )
    kernel.complete_activity(f"act-{rid}", payload=canonical_json({"kind": "a"}))
    await provider.inspect(handle)  # ledger records the first terminal hash
    kernel.complete_activity(
        f"act-{rid}", payload=canonical_json({"kind": "divergent"})
    )
    with pytest.raises(StableError) as excinfo:
        await provider.reconcile(
            eb.ReconcileRequest(
                session_id="sess",
                realm_id="realm://main",
                known=[eb.KnownBinding(request_id=rid, handle=handle)],
            )
        )
    assert excinfo.value.code == ErrorCode.INTEGRITY_ERROR


async def test_acknowledge_terminal_hash_checked(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    await provider.negotiate(make_hello())
    rid = new_request_id()
    handle = await provider.submit(
        make_request(rid, "test.echo", canonical_json({"kind": "echo"}))
    )
    result = await provider.await_activity(handle, 0)
    with pytest.raises(StableError) as excinfo:
        await provider.acknowledge_terminal(
            eb.TerminalAck(session_id="sess", request_id=rid, result_hash="00" * 32)
        )
    assert excinfo.value.code == ErrorCode.INTEGRITY_ERROR
    report = await provider.acknowledge_terminal(
        eb.TerminalAck(session_id="sess", request_id=rid, result_hash=result.result_hash)
    )
    assert report.status == "ACKED"
    assert report.retained_until_us > 0
    replay = await provider.acknowledge_terminal(
        eb.TerminalAck(session_id="sess", request_id=rid, result_hash=result.result_hash)
    )
    assert replay.retained_until_us == report.retained_until_us


async def test_close_session_is_advisory(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    session = await provider.negotiate(make_hello())
    handle = await provider.submit(
        make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    )
    report = await provider.close_session(session)
    assert report.status == "CLOSED"
    assert report.session_id == session.session_id
    # In-flight work is not cancelled; Await still resolves.
    result = await provider.await_activity(handle, 0)
    assert result.status == "COMPLETED"
    late = make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    late.session_id = session.session_id
    with pytest.raises(StableError) as excinfo:
        await provider.submit(late)
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION


async def test_authority_token_is_verified_and_never_forwarded(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    request = make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    request.authority_token = b"secret-token-bytes"
    with pytest.raises(StableError) as excinfo:
        await provider.submit(request)
    assert excinfo.value.code == ErrorCode.AUTHORITY_DENIED

    seen = {}

    def verifier(raw: bytes) -> str:
        seen["raw"] = raw
        return "principal://operator/agent-7"

    provider2 = make_provider(tmp_path / "v2", kernel, token_verifier=verifier)
    await provider2.negotiate(make_hello())
    request2 = make_request(new_request_id(), "test.echo", canonical_json({"kind": "echo"}))
    request2.authority_token = b"secret-token-bytes"
    await provider2.submit(request2)
    assert seen["raw"] == b"secret-token-bytes"
    submit_calls = [req for method, req in kernel.calls if method == "SubmitActivity"]
    assert submit_calls[-1].meta.claimed_principal_name == "principal://operator/agent-7"
    # The token bytes never cross the kernel boundary.
    assert all(b"secret-token-bytes" not in req.SerializeToString() for _, req in kernel.calls)


async def test_framed_unknown_method_and_response_envelope(tmp_path) -> None:
    provider = make_provider(tmp_path, FakeKernelTransport())
    envelope = build_envelope(
        method="agent_meta.execution_backend.v1.Backend.Bogus",
        payload=b"",
        request_id=new_request_id(),
    )
    response = transport.RpcEnvelope()
    response.ParseFromString(await provider.dispatch(envelope.SerializeToString()))
    assert response.error.code == ErrorCode.INVALID_ARGUMENT

    response_frame = build_envelope(
        method="agent_meta.execution_backend.v1.Backend.Negotiate",
        payload=b"",
        is_response=True,
        request_id=new_request_id(),
    )
    response = transport.RpcEnvelope()
    response.ParseFromString(await provider.dispatch(response_frame.SerializeToString()))
    assert response.error.code == ErrorCode.INTERNAL


async def test_framed_roundtrip_reports_kernel_error_mapping(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await framed(provider, "Negotiate", make_hello())
    rid = new_request_id()
    handle = await provider.submit(
        make_request(rid, "test.echo", canonical_json({"kind": "echo"}))
    )
    # The kernel forgets the activity (restart/retention): the handle-context
    # NOT_FOUND maps to HANDLE_EXPIRED on the wire (§2.3).
    kernel.drop_activity(f"act-{rid}")
    with pytest.raises(StableError) as excinfo:
        await framed(provider, "Await", handle)
    assert excinfo.value.code == ErrorCode.HANDLE_EXPIRED


async def test_kernel_call_uuid4_mapping_recorded(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await provider.negotiate(make_hello())
    rid = new_request_id()
    await provider.submit(make_request(rid, "test.echo", canonical_json({"kind": "echo"})))
    events = provider._ledger.events(rid)
    kernel_calls = [e for e in events if e["event_type"] == "kernel_call"]
    recorded = [json.loads(bytes(e["event_jcs"])) for e in kernel_calls]
    methods = {entry["method"] for entry in recorded}
    assert {"CreateRealm", "SpawnProcess", "SubmitActivity"} <= methods
    assert methods <= {
        "CreateRealm",
        "InspectRealm",
        "SpawnProcess",
        "InspectProcess",
        "SubmitActivity",
        "InspectActivity",
    }
    assert recorded
    for entry in recorded:
        parsed = uuid_module.UUID(entry["kernel_request_id"])
        assert parsed.version == 4


async def test_mapping_tables_follow_the_bridge_doc() -> None:
    from agent_meta_runtime.adapters.execution_agentos.mapping import (
        map_kernel_error,
        status_of,
        terminal_state,
    )

    assert status_of(ktypes.ACTIVITY_STATE_RUNNING) == "RUNNING"
    assert status_of(ktypes.ACTIVITY_STATE_SUSPENDED) == "RUNNING"
    assert status_of(ktypes.ACTIVITY_STATE_KILLING) == "CANCELLING"
    assert status_of(ktypes.ACTIVITY_STATE_COMPLETED) == "COMPLETED"
    assert status_of(ktypes.ACTIVITY_STATE_KILLED) == "FAILED"
    assert terminal_state(ktypes.ACTIVITY_STATE_TIMED_OUT)
    assert not terminal_state(ktypes.ACTIVITY_STATE_BLOCKED)

    assert map_kernel_error(kcommon.INVALID_ARGUMENT, "x").code == ErrorCode.INVALID_ARGUMENT
    assert map_kernel_error(kcommon.INVALID_STATE, "x").code == ErrorCode.FAILED_PRECONDITION
    assert map_kernel_error(kcommon.PERMISSION_DENIED, "x").code == ErrorCode.AUTHORITY_DENIED
    assert map_kernel_error(kcommon.ADMISSION_REJECTED, "x").code == ErrorCode.RESOURCE_EXHAUSTED
    assert map_kernel_error(kcommon.DEADLINE_EXCEEDED, "x").code == ErrorCode.DEADLINE_EXCEEDED
    assert map_kernel_error(kcommon.NOT_FOUND, "x").code == ErrorCode.NOT_FOUND
    assert (
        map_kernel_error(kcommon.NOT_FOUND, "x", handle_context=True).code
        == ErrorCode.HANDLE_EXPIRED
    )
    assert (
        map_kernel_error(kcommon.STALE_GENERATION, "x", handle_context=True).code
        == ErrorCode.HANDLE_EXPIRED
    )
    assert map_kernel_error(kcommon.QUORUM_LOSS, "x").code == ErrorCode.INTERNAL


async def test_deadline_and_trace_pass_into_request_meta(tmp_path) -> None:
    kernel = FakeKernelTransport()
    provider = make_provider(tmp_path, kernel)
    await framed(provider, "Negotiate", make_hello())
    payload = canonical_json({"kind": "echo"})
    request = make_request(new_request_id(), "test.echo", payload)
    request.deadline_at_us = time.time_ns() // 1000 + 60_000_000
    await framed(
        provider,
        "Submit",
        request,
        trace={"traceparent": "00-trace-span-01"},
    )
    submit_calls = [req for method, req in kernel.calls if method == "SubmitActivity"]
    meta = submit_calls[-1].meta
    assert is_uuid4(meta.request_id)
    assert meta.abi_version == "v1"
    assert meta.client_id == "agent-meta-runtime"
    assert meta.deadline.seconds > 0
    assert meta.trace_context["traceparent"] == "00-trace-span-01"


def is_uuid4(value: str) -> bool:
    parsed = uuid_module.UUID(value)
    return parsed.version == 4
