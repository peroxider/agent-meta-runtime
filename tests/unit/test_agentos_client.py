"""Step 04 tests: AgentOS client + fake provider contract gate (§41.48.2,
§41.27): a second provider behind the same framed eight-RPC contract."""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from agent_meta_runtime.adapters.execution_agentos import (
    AgentOSClient,
    AgentOSFakeProvider,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport


def make_request(rid, *, kind="test.echo", payload=None):
    body = json.dumps(payload if payload is not None else {"hello": "world"}, sort_keys=True).encode()
    return eb.ExecutionRequest(
        session_id="sess",
        realm_id="realm://main",
        request_id=rid,
        operation_kind=kind,
        payload_hash=hashlib.sha256(body).hexdigest(),
        payload_jcs=body,
        idempotency_class="KEYED",
        reversibility="REVERSIBLE",
        dedupe_scope="t",
        requested_retention_us=3_600_000_000,
    )


def make_hello(*required):
    return eb.ClientHello(
        supported=[transport.VersionRange(major=1, min_minor=0, max_minor=0)],
        client_instance_id="t",
        required_features=list(required),
    )


def test_fake_provider_reports_managed_profile(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path)
    caps = provider.capabilities()
    assert caps["profile"] == "MANAGED"
    # the fake never claims isolation capabilities the flow lacks (§41.48.4)
    assert caps["features"]["network_isolation"] == "UNSUPPORTED"


async def test_framed_negotiate_submit_await_inspect(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path, poll_interval_s=0.02)
    client = AgentOSClient(provider)
    session = await client.negotiate(make_hello("process", "workspace"))
    assert session.profile == "MANAGED"
    assert session.protocol_major == 1
    rid = str(uuid.uuid4())
    handle = await client.submit(make_request(rid))
    assert handle.request_id == rid
    result = await client.await_activity(handle, 0)
    assert result.status == "SUCCEEDED"
    snapshot = await client.inspect(handle)
    assert snapshot.status == "TERMINAL"
    assert snapshot.terminal.status == "SUCCEEDED"


async def test_framed_submit_idempotent_replay(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path, poll_interval_s=0.02)
    client = AgentOSClient(provider)
    rid = str(uuid.uuid4())
    handle = await client.submit(make_request(rid))
    replay = await client.submit(make_request(rid))
    assert replay.request_id == handle.request_id
    with pytest.raises(StableError) as exc:
        await client.submit(make_request(rid, payload={"x": 2}))
    assert exc.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


async def test_unknown_method_maps_to_invalid_argument(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path)
    client = AgentOSClient(provider)
    with pytest.raises(StableError) as exc:
        await client._call("Bogus", b"")
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT


async def test_cancel_terminal_fast_path_reports_result_status(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path, poll_interval_s=0.02)
    client = AgentOSClient(provider)
    rid = str(uuid.uuid4())
    handle = await client.submit(make_request(rid))
    await client.await_activity(handle, 0)
    report = await client.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL", deadline_at_us=0))
    assert report.terminal_confirmed
    assert report.status == "SUCCEEDED"


async def test_cancel_running_sleep_worker(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path, poll_interval_s=0.02)
    client = AgentOSClient(provider)
    rid = str(uuid.uuid4())
    handle = await client.submit(
        make_request(rid, kind="test.sleep", payload={"seconds": 30})
    )
    report = await client.cancel(eb.CancelRequest(handle=handle, mode="GRACEFUL", deadline_at_us=0))
    assert report.terminal_confirmed and report.status == "CANCELLED"


async def test_reconcile_ack_close_through_frames(tmp_path) -> None:
    provider = AgentOSFakeProvider(tmp_path, poll_interval_s=0.02)
    client = AgentOSClient(provider)
    await client.negotiate(make_hello())
    rid = str(uuid.uuid4())
    handle = await client.submit(make_request(rid))
    result = await client.await_activity(handle, 0)
    rec = await client.reconcile(
        eb.ReconcileRequest(session_id="sess", realm_id="realm://main",
                            known=[eb.KnownBinding(request_id=rid, handle=handle)])
    )
    assert rec.bindings[0].status == "TERMINAL"
    ack = await client.acknowledge_terminal(
        eb.TerminalAck(session_id="sess", request_id=rid, result_hash=result.result_hash)
    )
    assert ack.status == "ACKNOWLEDGED"
    closed = await client.close_session()
    assert closed.status == "CLOSED"
