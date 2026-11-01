"""Actual daemon -> token -> Backend -> callback -> durable terminal -> ack."""

import asyncio
import json
import os

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex
from agent_meta_runtime.domain.host_profile import INMEMORY_HOST_PROFILE_HASH
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.adapters import memory_host
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority


async def installed(root, bundle, manifest, grants):
    authority = _authority(root)
    daemon = RuntimeDaemon(root, allow_insecure_credentials=os.name != "nt", execution_backend="in_memory",
        trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
    await daemon.start()
    client = await connect(root, authority=authority)
    result = await upload_install(client, authority, bundle, manifest)
    await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=result.resource["harness_id"],
        composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
    await wait_refs(client, status="READY", serving=1)
    return daemon, client, authority


async def submit(client, authority, value="memory"):
    artifact = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id, content=canonical_json(value), kind="task_input", media_type="application/json")
    return await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=artifact["artifact_id"])


@pytest.mark.parametrize("lost_ack", [False, True])
def test_actual_backend_binding_and_durable_ack_restart(tmp_path, monkeypatch, lost_ack):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest, grants = live_bundle()
    async def scenario():
        daemon, client, authority = await installed(tmp_path, bundle, manifest, grants)
        real_ack = daemon._activities.backend.acknowledge_terminal
        observed = []
        async def ack(request):
            assert not daemon._conn.in_transaction
            row = daemon._conn.execute("SELECT status FROM invocations WHERE invocation_id=?", (request.request_id,)).fetchone()
            assert row == ("SUCCEEDED",)
            assert daemon._conn.execute("SELECT state FROM outbox WHERE kind='BACKEND_TERMINAL_ACK'").fetchone()[0] == "LEASED"
            observed.append(request.request_id)
            result = await real_ack(request)
            if lost_ack:
                raise OSError("response lost after actual Backend ack")
            return result
        monkeypatch.setattr(daemon._activities.backend, "acknowledge_terminal", ack)
        try:
            view = await client.get_view(include_backend=True)
            assert view["backend_profile"]["profile_hash"] == INMEMORY_HOST_PROFILE_HASH
            assert view["backend_profile"]["features"]["persistent_idempotency"] == "EMULATED"
            task = await submit(client, authority)
            terminal, done = await client.wait_task(task.task_id, timeout_s=5)
            assert done and terminal["status"] == "SUCCEEDED", terminal
            for _ in range(200):
                execution = await client.get_task_execution(task.task_id)
                binding = execution["invocations"][0]["execution_binding"]
                if observed and (lost_ack or binding["ack_state"] == "ACKNOWLEDGED"):
                    break
                await asyncio.sleep(.01)
            assert observed and binding["ack_state"] == ("PENDING" if lost_ack else "ACKNOWLEDGED")
            assert binding["backend_id"] == "backend://inmemory" and binding["terminal_status"] == "SUCCEEDED"
            row = daemon._conn.execute("SELECT handle_bytes,request_id,status FROM execution_bindings").fetchone()
            assert sha256_hex(row[0]) == binding["handle_hash"] and row[1:] == (binding["request_id"], "SUCCEEDED")
            assert not {"session_id", "opaque_handle", "authority_token"} & binding.keys()
            trace = await client.get_task_trace(task.task_id)
            assert any(edge["edge_type"] == "executed_as" for edge in trace["edges"])
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='execution_submitted'").fetchone()[0] == 1
            assert len(daemon._activities.backend.state._requests) == 1
            assert all(not record.request.authority_token for record in daemon._activities.backend.state._requests.values())
            expected = terminal["result_artifact_id"]
        finally:
            await client.aclose()
            await daemon.close()
        # The actual ephemeral Backend ledger is gone. Never claim an ACK or
        # resubmit the confirmed activity in a fresh session.
        restarted = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", execution_backend="in_memory",
            trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
        await restarted.start()
        client = await connect(tmp_path, authority=authority)
        try:
            for _ in range(250):
                execution = await client.get_task_execution(task.task_id)
                binding = execution["invocations"][0]["execution_binding"]
                if binding["ack_state"] != "PENDING":
                    break
                await asyncio.sleep(.01)
            assert binding["ack_state"] == ("UNAVAILABLE_SESSION_LOST" if lost_ack else "ACKNOWLEDGED")
            assert execution["result_artifact_id"] == expected
            assert len(restarted._activities.backend.state._requests) == 0
        finally:
            await client.aclose()
            await restarted.close()
    asyncio.run(scenario())


def test_invalid_token_is_denied_before_backend_callback(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest, grants = live_bundle()
    async def scenario():
        daemon, client, authority = await installed(tmp_path, bundle, manifest, grants)
        original = memory_host.issue_execution_token
        def rejected(*args, **kwargs):
            value = json.loads(original(*args, **kwargs))
            value["signature"] = "00" * 64
            return canonical_json(value)
        monkeypatch.setattr(memory_host, "issue_execution_token", rejected)
        try:
            task = await submit(client, authority)
            result, done = await client.wait_task(task.task_id, timeout_s=5)
            assert done and result["status"] == "FAILED" and result["error"] == "AUTHORITY_DENIED", result
            assert not daemon._activities.backend.state._requests
            assert daemon._conn.execute("SELECT COUNT(*) FROM execution_bindings").fetchone()[0] == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM outbox WHERE kind='BACKEND_TERMINAL_ACK'").fetchone()[0] == 0
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["cancel", "bind", "terminal_commit"])
def test_unconfirmed_activity_never_acknowledges_or_reexecutes(tmp_path, monkeypatch, failure):
    from agent_meta_runtime.adapters.store.uow import _SqliteStoreTransaction
    from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest, grants = live_bundle()
    async def scenario():
        daemon, client, authority = await installed(tmp_path, bundle, manifest, grants)
        calls = []
        execute = daemon._activities._execute
        async def observed(request):
            calls.append(request.request_id)
            return await execute(request)
        monkeypatch.setattr(daemon._activities.backend, "_executor", observed)
        if failure == "bind":
            def refused(*args, **kwargs):
                raise StableError(code=ErrorCode.INTERNAL, message="binding commit failed")
            monkeypatch.setattr(HostExecutionStore, "bind_backend", refused)
        elif failure == "terminal_commit":
            enqueue = _SqliteStoreTransaction.enqueue_outbox
            def refused(self, request):
                if request.kind == "BACKEND_TERMINAL_ACK":
                    raise StableError(code=ErrorCode.INTERNAL, message="terminal/ack atomic commit failed")
                return enqueue(self, request)
            monkeypatch.setattr(_SqliteStoreTransaction, "enqueue_outbox", refused)
        try:
            task = await submit(client, authority, "pending" if failure == "cancel" else "memory")
            if failure == "cancel":
                for _ in range(200):
                    if calls:
                        break
                    await asyncio.sleep(.01)
                assert calls
                await client.cancel_task(realm_id="realm://main", actor_id=authority.actor_id, task_id=task.task_id)
            terminal, done = await client.wait_task(task.task_id, timeout_s=5)
            assert done and terminal["status"] == ("CANCELLED" if failure == "cancel" else "FAILED"), terminal
            assert len(calls) == (0 if failure == "bind" else 1)
            assert daemon._conn.execute("SELECT COUNT(*) FROM outbox WHERE kind='BACKEND_TERMINAL_ACK'").fetchone()[0] == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='terminal_acknowledged'").fetchone()[0] == 0
            if failure != "bind":
                assert daemon._conn.execute("SELECT status FROM execution_bindings").fetchone()[0] == "UNKNOWN"
                execution = await client.get_task_execution(task.task_id)
                assert execution["invocations"][0]["execution_binding"]["terminal_status"] == "UNKNOWN"
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())
