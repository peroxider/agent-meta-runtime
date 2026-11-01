"""Real daemon owner/lock/store/transport lifecycle; no fixture readiness."""

import asyncio
import json
import os

import pytest

from agent_meta_runtime.adapters.credentials import operator_signing_authority
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import CommandAuthority, connect


def _init(path):
    return run_init(path, insecure_dev_credential_file=os.name != "nt")


def _authority(path):
    public, sign = operator_signing_authority(path, allow_insecure=os.name != "nt")
    return CommandAuthority(public["actor_id"], public["authority_grant_id"], sign)


def test_real_owner_connect_and_signed_shutdown(tmp_path):
    _init(tmp_path)
    async def scenario():
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        client = None
        try:
            status = await daemon.start()
            assert status["core_ready"] and not status["serving_ready"]
            client = await connect(tmp_path, authority=_authority(tmp_path))
            assert client.server_instance_id == daemon.instance_id
            info = await client.get_info()
            assert info.live and info.core_ready and not info.serving_ready
            result = await client.stop_runtime(realm_id="realm://main", actor_id=_authority(tmp_path).actor_id)
            assert result.resource["instance_id"] == daemon.instance_id
            assert result.resource["status"] == "STOPPING"
            await asyncio.wait_for(daemon.wait(), 2)
            metadata = json.loads((tmp_path / "run/daemon.lock").read_bytes())
            assert metadata["instance_id"] == daemon.instance_id
            if os.name == "nt":
                assert metadata["process_start_identity"].startswith("windows-filetime:")
        finally:
            if client is not None:
                await client.aclose()
            await daemon.close()
        other = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        try:
            await other.start()
            assert other.instance_id != daemon.instance_id
        finally:
            await other.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("revoked", ["principal", "grant"])
def test_host_control_rechecks_service_authority_before_any_mutation(tmp_path, revoked):
    _init(tmp_path)
    async def scenario():
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await daemon.start()
        called = []
        try:
            # Runtime-owned authority fault fixture, never an external Seed
            # shortcut. The production command runner must reject the write.
            if revoked == "principal":
                daemon._conn.execute("UPDATE principals SET status='REVOKED' WHERE principal_id=?", (daemon._service_id,))
            else:
                daemon._conn.execute("UPDATE authority_grants SET status='REVOKED' WHERE grant_id=?", (daemon._service_grant_id,))
            daemon._conn.commit()
            before = daemon._conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0]
            with pytest.raises(StableError) as denied:
                daemon._run_control(lambda txn: called.append(True) or {})
            assert denied.value.code == ErrorCode.AUTHORITY_DENIED
            assert called == []
            assert daemon._conn.execute("SELECT COUNT(*) FROM authority_uses").fetchone()[0] == before
        finally:
            await daemon.close()
    asyncio.run(scenario())


def test_unsigned_stop_and_wrong_incarnation_do_not_stop_owner(tmp_path):
    _init(tmp_path)
    async def scenario():
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await daemon.start()
        unsigned = await connect(tmp_path)
        signed = await connect(tmp_path, authority=_authority(tmp_path))
        try:
            with pytest.raises(StableError) as denied:
                await unsigned.stop_runtime(realm_id="realm://main", actor_id=_authority(tmp_path).actor_id)
            assert denied.value.code == ErrorCode.AUTHORITY_DENIED
            with pytest.raises(StableError) as wrong:
                await signed.stop_runtime(realm_id="realm://main", actor_id=_authority(tmp_path).actor_id, instance_id="different-instance")
            assert wrong.value.code == ErrorCode.FAILED_PRECONDITION
            assert (await signed.get_info()).live
            assert not daemon._shutdown.is_set()
        finally:
            await unsigned.aclose()
            await signed.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_old_stop_command_replay_does_not_stop_replacement_instance(tmp_path):
    _init(tmp_path)
    async def scenario():
        first = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await first.start()
        authority = _authority(tmp_path)
        client = await connect(tmp_path, authority=authority)
        raw = client.build_envelope_jcs(realm_id="realm://main", actor_id=authority.actor_id,
            payload_type="runtime.stop/v1", payload={"instance_id": first.instance_id, "reason_code": "test_stop"})
        try:
            receipt = await client.execute_command("agent_meta.public.v1.Runtime.Stop", raw)
            await asyncio.wait_for(first.wait(), 2)
        finally:
            await client.aclose()
            await first.close()
        second = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await second.start()
        client = await connect(tmp_path, authority=authority)
        try:
            assert await client.execute_command("agent_meta.public.v1.Runtime.Stop", raw) == receipt
            assert not second._shutdown.is_set()
            assert (await client.get_info()).live
            await client.stop_runtime(realm_id="realm://main", actor_id=authority.actor_id)
            await asyncio.wait_for(second.wait(), 2)
        finally:
            await client.aclose()
            await second.close()
    asyncio.run(scenario())


def test_exclusive_owner_and_root_revocation_readiness(tmp_path):
    import sqlite3
    _init(tmp_path)
    async def scenario():
        first = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        other = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await first.start()
        client = await connect(tmp_path)
        try:
            with pytest.raises(StableError) as duplicate:
                await other.start()
            assert duplicate.value.code == ErrorCode.ALREADY_RUNNING
            assert (await client.get_info()).core_ready
            # Runtime unit corruption/revocation fixture, not external consumer proof.
            conn = sqlite3.connect(tmp_path / "meta.db")
            conn.execute("UPDATE authority_grants SET status='REVOKED' WHERE subject_id=?", (_authority(tmp_path).actor_id,))
            conn.commit()
            conn.close()
            info = await client.get_info()
            assert not info.core_ready and "ROOT_AUTH_UNAVAILABLE" in info.core_reasons
        finally:
            await client.aclose()
            await other.close()
            await first.close()
    asyncio.run(scenario())


def test_api_10_connection_cannot_invoke_api_11_stop(tmp_path):
    import struct
    from agent_meta_runtime.sdk.transport import open_local_streams
    from agent_meta_runtime.protocols._v1 import transport_pb2 as wire
    from agent_meta_runtime.protocols._v1 import public_pb2 as pub
    from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope

    _init(tmp_path)
    async def scenario():
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await daemon.start()
        reader, writer = await open_local_streams(tmp_path / "run/agent-meta.sock")
        async def exchange(method, request, request_id):
            envelope = wire.RpcEnvelope(protocol_major=1, protocol_minor=0,
                method=method, request_id=request_id, payload=request.SerializeToString())
            writer.write(encode_frame(envelope.SerializeToString()))
            await writer.drain()
            length = struct.unpack(">I", await reader.readexactly(4))[0]
            return parse_envelope(await reader.readexactly(length))
        try:
            hello = await exchange("Hello", wire.HelloRequest(supported=[wire.VersionRange(major=1, min_minor=0, max_minor=0)]), "hello")
            chosen = wire.HelloResponse.FromString(hello.payload)
            assert chosen.selected_minor == 0
            denied = await exchange("agent_meta.public.v1.Runtime.Stop", pub.CommandRequest(), "stop")
            assert denied.error.code == ErrorCode.CONTRACT_INCOMPATIBLE
            assert not daemon._shutdown.is_set()
        finally:
            writer.close()
            await writer.wait_closed()
            await daemon.close()
    asyncio.run(scenario())


def test_rejected_stop_replay_keeps_original_error_after_restart(tmp_path, monkeypatch):
    from agent_meta_runtime.adapters.store import uow
    from agent_meta_runtime.domain.canonical import now_us

    _init(tmp_path)
    async def scenario():
        first = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await first.start()
        authority = _authority(tmp_path)
        client = await connect(tmp_path, authority=authority)
        raw = client.build_envelope_jcs(realm_id="realm://main", actor_id=authority.actor_id,
            payload_type="runtime.stop/v1", payload={"instance_id": first.instance_id, "reason_code": "clock_race"})
        try:
            # Authentication preview observes the original time; the transaction
            # rejects after a simulated wall jump. This records a durable denial.
            future = now_us() + 400_000_000
            with monkeypatch.context() as changed:
                changed.setattr(uow._CLOCK, "now_us", lambda: future)
                with pytest.raises(StableError) as denied:
                    await client.execute_command("agent_meta.public.v1.Runtime.Stop", raw)
                original = denied.value.to_json()
                assert original["details"]["reason_code"] == "SIGNATURE_STALE"
            assert not first._shutdown.is_set()
        finally:
            await client.aclose()
            await first.close()
        second = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await second.start()
        client = await connect(tmp_path, authority=authority)
        try:
            with pytest.raises(StableError) as replay:
                await client.execute_command("agent_meta.public.v1.Runtime.Stop", raw)
            assert replay.value.to_json() == original
            assert not second._shutdown.is_set()
        finally:
            await client.aclose()
            await second.close()
    asyncio.run(scenario())
