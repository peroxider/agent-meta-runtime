"""Actual InMemory admission/result contracts, distinct from Host proof."""

import asyncio
from dataclasses import replace
import json
import time

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.execution_memory import InMemoryBackend
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.ports.execution import ExecutionOutcome
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from test_execution_memory import make_hello, make_request
from test_execution_tokens import Chain, NOW


async def opened(**options):
    backend = InMemoryBackend(**options)
    return backend, await backend.negotiate(make_hello())


async def test_actual_signed_token_is_checked_before_executor_and_never_retained(tmp_path):
    chain, calls = Chain(), []
    cas = FilesystemCas(tmp_path)
    content = canonical_json({"normalized": "actual result"})
    reference = "artifact://sha256/" + sha256_hex(content)
    cas.put(content)
    def authorize(request):
        return chain.verifier.verify(bytes(request.authority_token), request_id=request.request_id,
            request_payload_hash=request.payload_hash, binding=chain.binding, now_us=NOW)
    async def execute(request):
        assert request.authority_token == b""
        calls.append(request.request_id)
        return ExecutionOutcome("SUCCEEDED", canonical_json({"cost_microunits": 0}), result_artifact_id=reference)
    backend, session = await opened(executor=execute, authorize=authorize)
    chain.binding = replace(chain.binding, backend_session_id=session.session_id)
    chain.payload["backend_session_id"] = session.session_id
    request = make_request("signed-model", session=session.session_id)
    request.authority_token = chain.token()
    handle = await backend.submit(request)
    result = await backend.await_activity(handle, 0)
    assert result.result_artifact_id == reference and result.result_hash == sha256_hex(reference.encode())
    assert calls == ["signed-model"] and backend.capabilities()["authorization"] == "INJECTED_VERIFIER"
    assert (await backend.submit(request)).opaque_handle == handle.opaque_handle and calls == ["signed-model"]
    assert bytes(request.authority_token) not in backend.state.to_bytes()
    denied = make_request("another-request", session=session.session_id)
    denied.authority_token = request.authority_token
    with pytest.raises(StableError) as error:
        await backend.submit(denied)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED
    assert calls == ["signed-model"] and len(backend.state._requests) == 1


@pytest.mark.parametrize("method", ["submit", "reconcile", "ack", "close"])
async def test_unknown_session_never_becomes_an_open_session(method):
    backend = InMemoryBackend()
    with pytest.raises(StableError) as error:
        if method == "submit":
            await backend.submit(make_request("unknown-session", session="not-negotiated"))
        elif method == "reconcile":
            await backend.reconcile(eb.ReconcileRequest(session_id="not-negotiated", realm_id="realm://main"))
        elif method == "ack":
            await backend.acknowledge_terminal(eb.TerminalAck(session_id="not-negotiated", request_id="missing", result_hash="0" * 64))
        else:
            await backend.close_session(eb.BackendSession(session_id="not-negotiated", backend_id="backend://inmemory"))
    assert error.value.code == ErrorCode.FAILED_PRECONDITION and not backend.state._requests


@pytest.mark.parametrize("field,value,code", [("backend_id", "backend://other", "AUTHORITY_DENIED"),
    ("request_id", "another-request", "AUTHORITY_DENIED"), ("session_id", "unknown", "FAILED_PRECONDITION"),
    ("incarnation", 99, "HANDLE_EXPIRED")])
async def test_forged_handles_cannot_read_another_result(field, value, code):
    backend, session = await opened()
    handle = await backend.submit(make_request("original", session=session.session_id))
    await backend.await_activity(handle, 0)
    forged = eb.ExecutionHandle()
    forged.CopyFrom(handle)
    setattr(forged, field, value)
    with pytest.raises(StableError) as error:
        await backend.inspect(forged)
    assert error.value.code == code
    assert (await backend.inspect(handle)).terminal.status == "SUCCEEDED"


@pytest.mark.parametrize("field,value", [("realm_id", "realm://other"), ("operation_kind", "test.other"),
    ("idempotency_class", "NONE"), ("reversibility", "COMPENSATABLE"),
    ("requested_retention_us", 123), ("deadline_at_us", NOW + 10_000_000), ("dedupe_scope", "another-scope")])
async def test_replay_cannot_change_any_effect_identity(field, value):
    backend, session = await opened()
    backend.state.set_clock(lambda: NOW)
    request = make_request("one-identity", session=session.session_id)
    handle = await backend.submit(request)
    altered = eb.ExecutionRequest()
    altered.CopyFrom(request)
    setattr(altered, field, value)
    with pytest.raises(StableError) as error:
        await backend.submit(altered)
    assert error.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert (await backend.await_activity(handle, 0)).status == "SUCCEEDED"
    assert len(backend.state._requests) == 1


async def test_retention_does_not_forget_unacknowledged_work_or_extend_ack_replay():
    now = [NOW]
    backend, session = await opened(maximum_requests=1)
    backend.state.set_clock(lambda: now[0])
    request = make_request("retained", session=session.session_id)
    request.requested_retention_us = 0
    handle = await backend.submit(request)
    result = await backend.await_activity(handle, 0)
    now[0] += 86_400_000_000
    with pytest.raises(StableError) as error:
        await backend.submit(make_request("new", session=session.session_id))
    assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED
    assert (await backend.submit(request)).opaque_handle == handle.opaque_handle
    with pytest.raises(StableError) as error:
        await backend.acknowledge_terminal(eb.TerminalAck(session_id=session.session_id, request_id="retained"))
    assert error.value.code == ErrorCode.REVISION_CONFLICT
    ack = eb.TerminalAck(session_id=session.session_id, request_id="retained", result_hash=result.result_hash)
    first = await backend.acknowledge_terminal(ack)
    now[0] += 1000
    assert await backend.acknowledge_terminal(ack) == first
    now[0] = first.retained_until_us
    next_handle = await backend.submit(make_request("after-retention", session=session.session_id))
    assert (await backend.await_activity(next_handle, 0)).status == "SUCCEEDED"
    with pytest.raises(StableError) as error:
        await backend.inspect(handle)
    assert error.value.code == ErrorCode.NOT_FOUND


async def test_byte_capacity_refuses_work_before_any_callback():
    calls = []
    async def execute(request):
        calls.append(request.request_id)
        return ExecutionOutcome("SUCCEEDED")
    backend, session = await opened(executor=execute, maximum_retained_bytes=1)
    with pytest.raises(StableError) as error:
        await backend.submit(make_request("no-space", session=session.session_id))
    assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED and calls == [] and not backend.state._requests


async def test_cancel_deadline_does_not_confirm_a_callback_that_suppresses_cancellation():
    started, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def execute(request):
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        finished.set()
        return ExecutionOutcome("SUCCEEDED")
    backend, session = await opened(executor=execute)
    handle = await backend.submit(make_request("suppressed", session=session.session_id))
    try:
        await asyncio.wait_for(started.wait(), 1)
        before = time.monotonic()
        cancelled = await backend.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL", deadline_at_us=backend.state.now_us() + 20_000))
        assert time.monotonic() - before < 1 and cancelled.status == "UNKNOWN" and not cancelled.terminal_confirmed
        assert not (await backend.cancel(eb.CancelRequest(handle=handle))).terminal_confirmed
        with pytest.raises(StableError) as error:
            await backend.await_activity(handle, 0)
        assert error.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
    finally:
        release.set()
        await asyncio.wait_for(finished.wait(), 1)
        await asyncio.sleep(0)
    assert (await backend.inspect(handle)).status == "UNKNOWN"
    assert backend.state._requests[("t", "suppressed")].result is None


async def test_terminal_conflict_and_executor_exception_never_replace_or_leak_result():
    backend, session = await opened()
    handle = await backend.submit(make_request("terminal", session=session.session_id))
    original = await backend.await_activity(handle, 0)
    assert backend.commit_terminal("terminal", "t", status="SUCCEEDED", usage_jcs=b"{}", incarnation=1) == original
    with pytest.raises(StableError) as error:
        backend.commit_terminal("terminal", "t", status="FAILED", error_jcs=b"{}", incarnation=1)
    assert error.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
    assert (await backend.await_activity(handle, 0)) == original
    async def fail(request):
        raise RuntimeError("unique-secret-marker")
    other, other_session = await opened(executor=fail)
    failure = await other.await_activity(await other.submit(make_request("failure", session=other_session.session_id)), 0)
    assert failure.status == "FAILED" and "unique-secret-marker" not in failure.error_jcs.decode()
    assert json.loads(failure.error_jcs)["code"] == ErrorCode.INTERNAL


async def test_closed_session_can_observe_existing_work_but_not_submit_more():
    backend, session = await opened()
    handle = await backend.submit(make_request("existing", session=session.session_id))
    await backend.close_session(session)
    assert (await backend.await_activity(handle, 0)).status == "SUCCEEDED"
    with pytest.raises(StableError) as error:
        await backend.submit(make_request("new", session=session.session_id))
    assert error.value.code == ErrorCode.FAILED_PRECONDITION
