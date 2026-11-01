"""ADR 040: bounded operator reads, not a simulated execution proof."""

import json
import struct

import pytest

from agent_meta_runtime.adapters.store.task_execution import task_execution
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.protocols._v1 import public_pb2 as pub, transport_pb2 as t
from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope
from test_local_server import ACTOR, _raw_hello, run_env


def test_missing_and_foreign_realm_inspection_never_return_task_records(tmp_path):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await client.submit_task(realm_id=env.realm, actor_id=ACTOR, input_artifact_id=env.input_artifact)
            before = env.conn.total_changes
            for task_id in ("task://" + new_uuid7(),):
                with pytest.raises(StableError) as error:
                    await client.get_task_execution(task_id)
                assert error.value.code == ErrorCode.NOT_FOUND
            with pytest.raises(StableError) as error:
                task_execution(env.conn, realm_id="realm://other", task_id=task.task_id)
            assert error.value.code == ErrorCode.NOT_FOUND
            one, two = await client.get_task_execution(task.task_id), await client.get_task_execution(task.task_id)
            assert one == two and env.conn.total_changes == before
            assert one["consumed_budget"] == {} and one["accepted_meta_revision"] > 0
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("ceiling", ["invocations", "projections", "bytes"])
def test_inspection_rejects_oversized_result_without_partial_success(tmp_path, ceiling):
    async def scenario(env):
        client = await connect(env.tmp_path, authority=env.authority)
        try:
            task = await client.submit_task(realm_id=env.realm, actor_id=ACTOR, input_artifact_id=env.input_artifact)
            # Runtime-owned read-bound fault fixtures; these rows do not claim
            # any package/backend actually executed, and are never Seed proofs.
            if ceiling == "invocations":
                env.conn.executemany("INSERT INTO invocations(invocation_id,action_id,kind,target,attempt,input_artifact_id,status,usage_json) "
                    "VALUES (?,?,'MODEL','query-fixture',1,?,'CREATED',?)", [
                        ("invocation://" + new_uuid7(), task.root_action_id, env.input_artifact, b"{}") for _ in range(1001)])
            elif ceiling == "projections":
                env.conn.executemany("INSERT INTO context_projections(projection_id,task_id,action_id,policy_artifact_id,composition_id,meta_revision,manifest_json,rendered_artifact_id,created_at_us) VALUES (?,?,?,?,?,1,?,?,1)", [
                    ("context://projection/" + new_uuid7(), task.task_id, task.root_action_id, env.input_artifact,
                     env.composition, b"{}", env.input_artifact) for _ in range(65)])
            else:
                env.conn.execute("INSERT INTO context_projections(projection_id,task_id,action_id,policy_artifact_id,composition_id,meta_revision,manifest_json,rendered_artifact_id,created_at_us) VALUES (?,?,?,?,?,1,?,?,1)",
                    ("context://projection/" + new_uuid7(), task.task_id, task.root_action_id, env.input_artifact,
                     env.composition, json.dumps({"fixture": "x" * 1024 * 1024}).encode(), env.input_artifact))
            before = env.conn.total_changes
            with pytest.raises(StableError) as error:
                await client.get_task_execution(task.task_id)
            assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED
            assert env.conn.total_changes == before
        finally:
            await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("minor", [0, 1])
def test_old_negotiated_minors_refuse_execution_inspection_before_handler(tmp_path, minor):
    async def scenario(env):
        dispatched = []
        async def forbidden(request, deadline):
            dispatched.append(request)
            raise AssertionError("old client reached new handler")
        env.server._handlers["agent_meta.public.v1.Task.GetExecution"] = forbidden
        reader, writer = await _raw_hello(env.socket_path, minor=minor)()
        try:
            frame = t.RpcEnvelope(protocol_major=1, protocol_minor=minor, request_id="inspect-old",
                method="agent_meta.public.v1.Task.GetExecution", payload=pub.GetTaskRequest(task_id="task://" + new_uuid7()).SerializeToString())
            writer.write(encode_frame(frame.SerializeToString()))
            await writer.drain()
            length = struct.unpack(">I", await reader.readexactly(4))[0]
            response = parse_envelope(await reader.readexactly(length))
            assert response.error.code == ErrorCode.CONTRACT_INCOMPATIBLE and not dispatched
        finally:
            writer.close()
            await writer.wait_closed()
    run_env(scenario, tmp_path)


def test_sdk_refuses_new_method_before_writing_to_older_negotiated_server(tmp_path, monkeypatch):
    from agent_meta_runtime.interfaces.local_api import server
    monkeypatch.setattr(server, "PUBLIC_API_MINOR", 1)
    async def scenario(env):
        assert env.client.negotiated_version == (1, 1)
        writes = []
        original = env.client._writer.write
        monkeypatch.setattr(env.client._writer, "write", writes.append)
        try:
            with pytest.raises(StableError) as error:
                await env.client.call("agent_meta.public.v1.Task.GetExecution", pub.GetTaskRequest(task_id="task://" + new_uuid7()), pub.ResourceResponse)
            assert error.value.code == ErrorCode.CONTRACT_INCOMPATIBLE and not writes
        finally:
            monkeypatch.setattr(env.client._writer, "write", original)
        frames = []
        def record(data):
            frames.append(data)
            original(data)
        monkeypatch.setattr(env.client._writer, "write", record)
        assert (await env.client.call("agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo)).live
        assert len(frames) == 1 and parse_envelope(frames[0][4:]).protocol_minor == 1
    run_env(scenario, tmp_path)
