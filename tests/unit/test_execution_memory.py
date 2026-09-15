"""Step 04 tests: InMemory contract backend + durable fake state (§41.48.2)."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from agent_meta_runtime.adapters.execution_memory import (
    DurableFakeBackendState,
    InMemoryBackend,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport


def make_request(rid, *, payload=None, scope="t", rev="REVERSIBLE", kind="test.echo",
                 session="sess"):
    body = json.dumps(payload if payload is not None else {"hello": "world"}, sort_keys=True).encode()
    return eb.ExecutionRequest(
        session_id=session,
        realm_id="realm://main",
        request_id=rid,
        operation_kind=kind,
        payload_hash=hashlib.sha256(body).hexdigest(),
        payload_jcs=body,
        idempotency_class="KEYED",
        reversibility=rev,
        dedupe_scope=scope,
        requested_retention_us=3_600_000_000,
    )


def make_hello(*required):
    return eb.ClientHello(
        supported=[transport.VersionRange(major=1, min_minor=0, max_minor=0)],
        client_instance_id="test",
        required_features=required,
    )


def test_capabilities_are_honest() -> None:
    backend = InMemoryBackend()
    caps = backend.capabilities()
    assert caps["profile"] == "PORTABLE"
    assert caps["features"]["persistent_idempotency"] == "EMULATED"
    assert caps["features"]["isolated_realm"] == "UNSUPPORTED"


async def test_negotiate_grants_features() -> None:
    backend = InMemoryBackend()
    session = await backend.negotiate(make_hello("process", "activity"))
    assert session.protocol_major == 1
    assert session.backend_id == "backend://inmemory"
    with pytest.raises(StableError) as exc:
        await backend.negotiate(make_hello("network_isolation"))
    assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE


async def test_submit_run_and_result_hash() -> None:
    backend = InMemoryBackend()
    request = make_request("req-1")
    handle = await backend.submit(request)
    assert handle.request_id == "req-1"
    assert handle.incarnation == 1
    result = await backend.await_activity(handle, 0)
    assert result.status == "SUCCEEDED"
    assert result.request_id == "req-1"
    assert result.result_hash
    snapshot = await backend.inspect(handle)
    assert snapshot.status == "TERMINAL"
    assert snapshot.terminal.status == "SUCCEEDED"


async def test_submit_idempotent_replay_and_hash_conflict() -> None:
    backend = InMemoryBackend()
    handle = await backend.submit(make_request("req-1"))
    replay = await backend.submit(make_request("req-1"))
    assert replay.opaque_handle == handle.opaque_handle
    with pytest.raises(StableError) as exc:
        await backend.submit(make_request("req-1", payload={"x": 2}))
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


async def test_payload_hash_mismatch_rejected() -> None:
    backend = InMemoryBackend()
    request = make_request("req-1")
    request.payload_hash = "0" * 64
    with pytest.raises(StableError) as exc:
        await backend.submit(request)
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT


async def test_high_risk_reversibility_rejected() -> None:
    backend = InMemoryBackend()
    for rev in ("IRREVERSIBLE", "UNKNOWN"):
        with pytest.raises(StableError) as exc:
            await backend.submit(make_request(f"req-{rev}", rev=rev))
        assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE


async def test_unregistered_operation_kind_rejected() -> None:
    backend = InMemoryBackend()
    with pytest.raises(StableError) as exc:
        await backend.submit(make_request("req-1", kind="fs.real_write"))
    assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE


async def test_cancel_graceful_and_force_unknown() -> None:
    async def slow(request):
        await asyncio.sleep(30)
        return "SUCCEEDED", b"{}", b"{}"

    backend = InMemoryBackend(executor=slow)
    handle = await backend.submit(make_request("req-slow"))
    report = await backend.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL"))
    assert report.terminal_confirmed
    assert report.status == "CANCELLED"

    handle2 = await backend.submit(make_request("req-force"))
    report2 = await backend.cancel(eb.CancelRequest(handle=handle2, mode="FORCE"))
    assert not report2.terminal_confirmed
    assert report2.status == "UNKNOWN"
    with pytest.raises(StableError) as exc:
        await backend.await_activity(handle2, 0)
    assert exc.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN


async def test_stale_incarnation_cannot_commit() -> None:
    backend = InMemoryBackend()
    handle = await backend.submit(make_request("req-1"))
    await backend.await_activity(handle, 0)
    backend.renew_incarnation("req-1", "t")
    with pytest.raises(StableError) as exc:
        backend.commit_terminal(
            "req-1", "t", status="SUCCEEDED", usage_jcs=b"{}", error_jcs=b"{}",
            incarnation=1,
        )
    assert exc.value.code == ErrorCode.REVISION_CONFLICT


async def test_await_deadline_exceeded_carries_status() -> None:
    async def slow(request):
        await asyncio.sleep(30)
        return "SUCCEEDED", b"{}", b"{}"

    backend = InMemoryBackend(executor=slow)
    state = backend.state
    handle = await backend.submit(make_request("req-1"))
    with pytest.raises(StableError) as exc:
        await backend.await_activity(handle, state.now_us() + 1_000)
    assert exc.value.code == ErrorCode.DEADLINE_EXCEEDED
    assert exc.value.details["status"] == "RUNNING"


async def test_durable_fake_state_restart_recovers() -> None:
    async def slow(request):
        await asyncio.sleep(30)
        return "SUCCEEDED", b"{}", b"{}"

    state = DurableFakeBackendState()
    backend = InMemoryBackend(state, executor=slow)
    handle = await backend.submit(make_request("req-live"))
    raw = state.to_bytes()

    restored_state = DurableFakeBackendState()
    restored_state.restore_bytes(raw)
    restored = InMemoryBackend(restored_state)
    # replayed submit on a live-less RUNNING record re-spawns (recovery)
    handle2 = await restored.submit(make_request("req-live"))
    assert handle2.request_id == "req-live"
    assert handle2.incarnation >= handle.incarnation
    # unknown request ids still 404
    with pytest.raises(StableError) as exc:
        await restored.inspect(eb.ExecutionHandle(opaque_handle=b"nope", incarnation=1))
    assert exc.value.code == ErrorCode.NOT_FOUND


async def test_reconcile_bindings_and_orphans() -> None:
    backend = InMemoryBackend()
    handle = await backend.submit(make_request("req-1"))
    await backend.await_activity(handle, 0)

    async def slow(request):
        await asyncio.sleep(30)
        return "SUCCEEDED", b"{}", b"{}"

    backend._executor = slow
    await backend.submit(make_request("req-orphan"))
    report = await backend.reconcile(
        eb.ReconcileRequest(session_id="sess", realm_id="realm://main",
                            known=[eb.KnownBinding(request_id="req-1")])
    )
    assert len(report.bindings) == 1
    assert report.bindings[0].status == "TERMINAL"
    assert report.bindings[0].terminal.status == "SUCCEEDED"
    orphan_ids = [o.request_id for o in report.orphans]
    assert "req-orphan" in orphan_ids


async def test_acknowledge_terminal_hash_checked() -> None:
    backend = InMemoryBackend()
    handle = await backend.submit(make_request("req-1"))
    result = await backend.await_activity(handle, 0)
    ack = await backend.acknowledge_terminal(
        eb.TerminalAck(session_id="sess", request_id="req-1",
                       result_hash=result.result_hash)
    )
    assert ack.status == "ACKNOWLEDGED"
    with pytest.raises(StableError) as exc:
        await backend.acknowledge_terminal(
            eb.TerminalAck(session_id="sess", request_id="req-1", result_hash="0" * 64)
        )
    assert exc.value.code == ErrorCode.REVISION_CONFLICT


async def test_closed_session_rejects_submit() -> None:
    backend = InMemoryBackend()
    session = await backend.negotiate(make_hello())
    await backend.close_session(session)
    with pytest.raises(StableError) as exc:
        await backend.submit(make_request("req-1", session=session.session_id))
    assert exc.value.code == ErrorCode.FAILED_PRECONDITION
