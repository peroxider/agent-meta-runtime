"""Public SDK over the platform's real local transport (no TCP fallback)."""

import asyncio
from contextlib import contextmanager
import os
import time

import pytest
from agent_meta_runtime.sdk import ErrorCode, StableError, connect
from agent_meta_runtime.sdk.transport import LocalConnection, open_local_streams
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from tests.unit.test_local_server import run_env


def test_public_sdk_connect_and_concurrent_calls(tmp_path):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            info, refs, view = await asyncio.gather(client.get_info(), client.get_refs(), client.get_view())
            assert info.core_ready and refs["serving_revision"] == view["serving_revision"] == 1
        finally:
            await client.aclose()

    run_env(scenario, tmp_path)


def test_expired_rpc_deadline_does_not_dispatch(tmp_path):
    async def scenario(env):
        with pytest.raises(StableError) as error:
            await env.client.call("agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo, deadline_us=time.time_ns() // 1000 - 1)
        assert error.value.code == ErrorCode.DEADLINE_EXCEEDED

    run_env(scenario, tmp_path)


def test_zero_wait_returns_nonterminal_snapshot_without_closing_task(tmp_path):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            handle = await client.submit_task(realm_id=env.realm, actor_id="principal://operator-root/01900000-0000-7000-8000-000000000000", input_artifact_id=env.input_artifact)
            task, terminal = await client.wait_task(handle.task_id, timeout_s=0)
            assert not terminal and task["status"] == "ACCEPTED"
        finally:
            await client.aclose()

    run_env(scenario, tmp_path)


def test_timeout_or_cancellation_closes_channel_before_next_request(tmp_path):
    async def scenario(env):
        connection = LocalConnection(env.socket_path)
        await connection.connect()
        server_seen = asyncio.Event()

        async def slow(request, deadline):
            server_seen.set()
            await asyncio.sleep(2)
            return pub.RuntimeInfo(live=True)

        env.server._handlers["agent_meta.public.v1.Runtime.GetInfo"] = slow
        request = asyncio.create_task(connection.call("agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo))
        await asyncio.wait_for(server_seen.wait(), 1)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        with pytest.raises(StableError) as error:
            await connection.call("agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo)
        assert error.value.code == ErrorCode.FAILED_PRECONDITION

    run_env(scenario, tmp_path)


def test_stable_error_survives_contextmanager_traceback_propagation():
    @contextmanager
    def around():
        yield

    error = StableError(code=ErrorCode.AUTHORITY_DENIED, message="denied")
    with pytest.raises(StableError) as captured:
        with around():
            raise error
    assert captured.value is error
    assert error.args == ("denied",)


@pytest.mark.skipif(os.name != "nt", reason="Windows Named Pipe identity boundary")
def test_named_pipe_peer_denial_precedes_hello_or_handler(tmp_path, monkeypatch):
    from agent_meta_runtime.sdk import _windows_peer

    real = _windows_peer.require_same_pipe_user
    server_checks = []

    async def scenario(env):
        def denied(pipe, *, server_side):
            if server_side:
                server_checks.append(True)
                raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="different test SID")
            return real(pipe, server_side=server_side)

        monkeypatch.setattr(_windows_peer, "require_same_pipe_user", denied)
        reader, writer = await open_local_streams(env.socket_path)
        try:
            assert await asyncio.wait_for(reader.read(), 1) == b""
            assert server_checks
        finally:
            writer.close()
            await writer.wait_closed()

    run_env(scenario, tmp_path)
