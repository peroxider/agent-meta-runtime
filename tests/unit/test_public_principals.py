"""ADR 044: ordinary keys and authority cross actual signed IPC boundaries."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.interfaces.cli import build_parser
from agent_meta_runtime.interfaces.cli.main import cmd_authority
from agent_meta_runtime.protocols._v1 import public_pb2 as pub, transport_pb2 as t
from agent_meta_runtime.protocols.public_wire import encode_frame, parse_envelope
from agent_meta_runtime.sdk import AgentMetaClient, CommandAuthority, connect, decode_command, encode_command, sign_command
from test_local_server import ACTOR, _raw_hello, make_envelope, run_env


@asynccontextmanager
async def root_client(env):
    client = await connect(env.tmp_path, authority=env.authority)
    try:
        yield client
    finally:
        await client.aclose()


async def identity(env, root, *, kind="AGENT"):
    key = Ed25519PrivateKey.generate()
    result = await root.create_principal(realm_id=env.realm, actor_id=ACTOR, kind=kind,
        public_key=key.public_key().public_bytes_raw())
    return result.resource["principal_id"], key


def scope(env, *targets):
    return {"realm_id": env.realm, "targets": list(targets) or [{"type": "REALM_ALL"}]}


async def delegate(env, root, subject, permissions, **kwargs):
    return (await root.delegate_authority(realm_id=env.realm, actor_id=ACTOR,
        subject_id=subject, permissions=permissions, scope=kwargs.pop("scope", scope(env)), **kwargs)).resource


def counts(env):
    return {table: env.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("principals", "authority_grants", "authority_uses", "facts", "commands", "tasks")}


def business_unchanged(env, before):
    after = counts(env)
    assert {k: v for k, v in after.items() if k != "commands"} == {k: v for k, v in before.items() if k != "commands"}
    # A rejected command can retain its durable rejection receipt, never its
    # rolled-back authority reservation or business rows.
    assert after["commands"] - before["commands"] in (0, 1)
    if after["commands"] != before["commands"]:
        assert env.conn.execute("SELECT status FROM commands ORDER BY rowid DESC LIMIT 1").fetchone()[0] == "REJECTED"
    return True


async def raw(env, method, payload_type, payload):
    return await env.client.call("agent_meta.public.v1.Authority." + method,
        pub.CommandRequest(command_envelope_jcs=canonical_json(make_envelope(env.realm, payload_type, payload))), pub.MutationResponse)


@pytest.mark.parametrize("kind", ["AGENT", "CAPABILITY", "PEER"])
def test_public_identity_is_immutable_and_confers_no_implicit_grant(tmp_path, kind):
    async def scenario(env):
        async with root_client(env) as root:
            subject, key = await identity(env, root, kind=kind)
            assert subject.startswith("principal://" + kind.lower() + "/")
            before = counts(env)
            same = await root.create_principal(realm_id=env.realm, actor_id=ACTOR, kind=kind,
                principal_id=subject, public_key=key.public_key().public_bytes_raw())
            assert same.resource["public_identity"]["public_key_hex"] == key.public_key().public_bytes_raw().hex()
            assert counts(env)["principals"] == before["principals"]
            assert counts(env)["authority_grants"] == before["authority_grants"]
            assert env.conn.execute("SELECT COUNT(*) FROM facts WHERE entity_id=? AND event_type='principal_registered'", (subject,)).fetchone()[0] == 1
            before = counts(env)
            with pytest.raises(StableError) as error:
                await root.create_principal(realm_id=env.realm, actor_id=ACTOR, kind=kind,
                    principal_id=subject, public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw())
            assert error.value.code == ErrorCode.ALREADY_EXISTS and business_unchanged(env, before)
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("fields", [
    {"kind": "SERVICE"}, {"kind": "OPERATOR_ROOT"}, {"kind": True}, {"kind": []},
    {"public_key_hex": "AB" * 32}, {"public_key_hex": "a" * 63}, {"public_key_hex": None},
    {"public_key_hex": "zz" * 32}, {"principal_id": ACTOR}, {"principal_id": 1}, {"extra": True},
])
def test_bad_registration_is_refused_without_any_write(tmp_path, fields):
    async def scenario(env):
        payload = {"kind": "AGENT", "public_key_hex": "ab" * 32, **fields}
        before = counts(env)
        with pytest.raises(StableError) as error:
            await raw(env, "CreatePrincipal", "authority.principal.create/v1", payload)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT and counts(env) == before
    run_env(scenario, tmp_path)


def test_one_remaining_parent_use_delegates_once_and_replay_does_not_charge(tmp_path):
    async def scenario(env):
        async with root_client(env) as root:
            actor, key = await identity(env, root)
            subject, _ = await identity(env, root)
            grant = await delegate(env, root, actor, ["authority.delegate", "task.submit"],
                constraints={"max_uses": 1}, delegable=True)
            client = await connect(env.tmp_path, authority=CommandAuthority(actor, grant["grant_id"], key.sign))
            try:
                envelope = client.build_envelope_jcs(realm_id=env.realm, actor_id=actor, payload_type="authority.delegate/v1",
                    payload={"subject_id": subject, "permissions": ["task.submit"], "scope": scope(env), "constraints": {"max_uses": 1}})
                result = await client.execute_command("agent_meta.public.v1.Authority.Delegate", envelope)
                assert result.resource["parent_grant_id"] == grant["grant_id"] and result.resource["issuer_id"] == actor
                uses = env.conn.execute("SELECT use_kind FROM authority_uses WHERE grant_id=?", (grant["grant_id"],)).fetchall()
                assert uses == [("command",)]
                before = counts(env)
                assert await client.execute_command("agent_meta.public.v1.Authority.Delegate", envelope) == result
                assert counts(env) == before
                with pytest.raises(StableError) as error:
                    await client.delegate_authority(realm_id=env.realm, actor_id=actor, subject_id=subject,
                        permissions=["task.submit"], scope=scope(env), constraints={"max_uses": 1})
                assert error.value.code == ErrorCode.AUTHORITY_DENIED and business_unchanged(env, before)
            finally:
                await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("dimension", ["permission", "scope", "second_scope", "max_uses", "expiry", "not_before", "epoch", "depth"])
def test_delegation_cannot_expand_any_parent_dimension(tmp_path, dimension):
    async def scenario(env):
        async with root_client(env) as root:
            actor, key = await identity(env, root)
            subject, _ = await identity(env, root)
            epoch = env.conn.execute("SELECT epoch_id FROM realms").fetchone()[0]
            target = {"type": "TASK", "id": "task://" + new_uuid7()}
            parent_scope = scope(env, target)
            limits = {"max_uses": 10, "not_before_us": 1, "expires_at_us": time.time_ns() // 1000 + 60_000_000,
                "epoch_id": epoch, "delegation_depth_remaining": 2}
            grant = await delegate(env, root, actor, ["authority.delegate", "task.cancel"],
                scope=parent_scope, constraints=limits, delegable=True)
            child_limits = {**limits, "delegation_depth_remaining": 1}
            permissions, child_scope = ["task.cancel"], parent_scope
            if dimension == "permission":
                permissions = ["task.submit"]
            elif dimension == "scope":
                child_scope = scope(env)
            elif dimension == "second_scope":
                child_scope = scope(env, target, {"type": "TASK", "id": "task://" + new_uuid7()})
            elif dimension == "max_uses":
                child_limits["max_uses"] = 11
            elif dimension == "expiry":
                child_limits["expires_at_us"] += 1
            elif dimension == "not_before":
                child_limits["not_before_us"] = 0
            elif dimension == "epoch":
                child_limits.pop("epoch_id")
            else:
                child_limits["delegation_depth_remaining"] = 2
            client = await connect(env.tmp_path, authority=CommandAuthority(actor, grant["grant_id"], key.sign))
            try:
                before = counts(env)
                with pytest.raises(StableError) as error:
                    await client.delegate_authority(realm_id=env.realm, actor_id=actor, subject_id=subject,
                        permissions=permissions, scope=child_scope, constraints=child_limits)
                assert error.value.code == ErrorCode.AUTHORITY_DENIED and business_unchanged(env, before)
                child = await client.delegate_authority(realm_id=env.realm, actor_id=actor, subject_id=subject,
                    permissions=["task.cancel"], scope=parent_scope, constraints={**limits, "delegation_depth_remaining": 0})
                assert child.resource["delegation_depth"] == 0
            finally:
                await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("case", ["unknown", "inactive", "foreign", "service", "root"])
def test_delegation_requires_active_ordinary_subject_in_the_same_realm(tmp_path, case):
    async def scenario(env):
        async with root_client(env) as root:
            subject, _ = await identity(env, root)
            if case == "unknown":
                subject = "principal://agent/" + new_uuid7()
            elif case == "inactive":
                env.conn.execute("UPDATE principals SET status='REVOKED' WHERE principal_id=?", (subject,))
                env.conn.commit()
            elif case == "foreign":
                from agent_meta_runtime.adapters.store import bootstrap_realm
                bootstrap_realm(env.conn, "realm://other", "epoch://" + new_uuid7())
                env.conn.execute("UPDATE principals SET realm_id='realm://other' WHERE principal_id=?", (subject,))
                env.conn.commit()
            elif case == "service":
                subject = "principal://service/01900000-0000-7000-8000-000000000001"
            else:
                subject = ACTOR
            before = counts(env)
            with pytest.raises(StableError) as error:
                await delegate(env, root, subject, ["task.submit"])
            expected = ErrorCode.NOT_FOUND if case in ("unknown", "foreign") else ErrorCode.FAILED_PRECONDITION if case == "inactive" else ErrorCode.AUTHORITY_DENIED
            assert error.value.code == expected and business_unchanged(env, before)
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("case", ["permission", "unrelated_owner", "partial_scope"])
def test_revoke_requires_permission_ownership_and_full_scope(tmp_path, case):
    async def scenario(env):
        async with root_client(env) as root:
            actor, key = await identity(env, root)
            other, _ = await identity(env, root)
            first = {"type": "TASK", "id": "task://" + new_uuid7()}
            second = {"type": "TASK", "id": "task://" + new_uuid7()}
            target = await delegate(env, root, actor if case != "unrelated_owner" else other,
                ["task.cancel"], scope=scope(env, first, second))
            authority = await delegate(env, root, actor, ["task.cancel"] if case == "permission" else ["authority.revoke"],
                scope=scope(env, first) if case == "partial_scope" else scope(env))
            client = await connect(env.tmp_path, authority=CommandAuthority(actor, authority["grant_id"], key.sign))
            try:
                before = counts(env)
                with pytest.raises(StableError) as error:
                    await client.revoke_authority(realm_id=env.realm, actor_id=actor, grant_id=target["grant_id"])
                assert error.value.code == ErrorCode.AUTHORITY_DENIED and business_unchanged(env, before)
            finally:
                await client.aclose()
    run_env(scenario, tmp_path)


def test_subject_can_revoke_own_grant_and_only_exact_committed_replay_survives(tmp_path):
    async def scenario(env):
        async with root_client(env) as root:
            actor, key = await identity(env, root)
            grant = await delegate(env, root, actor, ["authority.revoke", "task.submit"])
            client = await connect(env.tmp_path, authority=CommandAuthority(actor, grant["grant_id"], key.sign))
            try:
                task_envelope = client.build_envelope_jcs(realm_id=env.realm, actor_id=actor,
                    payload_type="task.submit/v1", payload={"input_artifact_id": env.input_artifact})
                task = await client.execute_command("agent_meta.public.v1.Task.Submit", task_envelope)
                revoked = await client.revoke_authority(realm_id=env.realm, actor_id=actor, grant_id=grant["grant_id"])
                assert revoked.resource["status"] == "REVOKED"
                before = counts(env)
                assert await client.execute_command("agent_meta.public.v1.Task.Submit", task_envelope) == task
                with pytest.raises(StableError) as error:
                    await client.submit_task(realm_id=env.realm, actor_id=actor, input_artifact_id=env.input_artifact)
                assert error.value.code == ErrorCode.AUTHORITY_DENIED and counts(env) == before
                forged = sign_command(replace(decode_command(task_envelope), payload={"input_artifact_id": env.input_artifact, "budget": {"max_steps": 1}}),
                    CommandAuthority(actor, grant["grant_id"], key.sign))
                with pytest.raises(StableError) as error:
                    await client.execute_command("agent_meta.public.v1.Task.Submit", encode_command(forged))
                assert error.value.code == ErrorCode.IDEMPOTENCY_CONFLICT and counts(env) == before
            finally:
                await client.aclose()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("payload", [
    {"constraints": {"max_uses": True}}, {"constraints": {"max_uses": 1.5}},
    {"constraints": {"max_uses": -1}}, {"constraints": {"max_uses": None}},
    {"constraints": {"unbounded": True}}, {"delegable": 1}, {"permissions": []},
    {"scope": {"realm_id": "realm://main", "targets": []}}, {"issuer_grant_id": "grant://" + new_uuid7()},
    {"scope": {"realm_id": "realm://main", "targets": [{"type": "TASK", "id": "not-an-id"}]}},
    {"scope": {"realm_id": "realm://main", "targets": [{"type": "HARNESS", "id": "task://" + new_uuid7()}]}},
])
def test_raw_delegation_rejects_coercion_and_hidden_issuer_fields(tmp_path, payload):
    async def scenario(env):
        async with root_client(env) as root:
            subject, _ = await identity(env, root)
            before = counts(env)
            with pytest.raises(StableError) as error:
                await raw(env, "Delegate", "authority.delegate/v1", {"subject_id": subject,
                    "permissions": ["task.submit"], "scope": scope(env), **payload})
            assert error.value.code == ErrorCode.INVALID_ARGUMENT and counts(env) == before
    run_env(scenario, tmp_path)


def test_unenforced_amount_ceiling_is_explicitly_unavailable_and_root_is_protected(tmp_path):
    async def scenario(env):
        async with root_client(env) as root:
            subject, _ = await identity(env, root)
            before = counts(env)
            with pytest.raises(StableError) as error:
                await raw(env, "Delegate", "authority.delegate/v1", {"subject_id": subject, "permissions": ["task.submit"],
                    "scope": scope(env), "constraints": {"resource_ceiling": {"cost_micro_usd": 0}}})
            assert error.value.code == ErrorCode.FEATURE_UNAVAILABLE and counts(env) == before
            with pytest.raises(StableError) as error:
                await root.revoke_authority(realm_id=env.realm, actor_id=ACTOR, grant_id=env.authority.authority_grant_id)
            assert error.value.code == ErrorCode.AUTHORITY_DENIED and business_unchanged(env, before)
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("fields", [{"grant_id": {}}, {"grant_id": []}, {"grant_id": True},
    {"grant_id": None}, {"grant_id": "task://" + new_uuid7()}, {"reason_code": False},
    {"reason_code": ""}, {"extra": 1}])
def test_bad_revocation_payload_has_stable_error_and_no_write(tmp_path, fields):
    async def scenario(env):
        before = counts(env)
        with pytest.raises(StableError) as error:
            await raw(env, "Revoke", "authority.revoke/v1", {"grant_id": "grant://" + new_uuid7(), **fields})
        assert error.value.code == ErrorCode.INVALID_ARGUMENT and counts(env) == before
    run_env(scenario, tmp_path)


def test_issuer_can_revoke_its_delegation_but_cannot_touch_runtime_service_grant(tmp_path):
    async def scenario(env):
        async with root_client(env) as root:
            actor, key = await identity(env, root)
            subject, _ = await identity(env, root)
            authority = await delegate(env, root, actor, ["authority.delegate", "authority.revoke", "task.cancel"], delegable=True)
            client = await connect(env.tmp_path, authority=CommandAuthority(actor, authority["grant_id"], key.sign))
            try:
                child = await client.delegate_authority(realm_id=env.realm, actor_id=actor, subject_id=subject,
                    permissions=["task.cancel"], scope=scope(env))
                assert child.resource["issuer_id"] == actor
                revoked = await client.revoke_authority(realm_id=env.realm, actor_id=actor, grant_id=child.resource["grant_id"])
                assert revoked.resource["status"] == "REVOKED"
                assert env.conn.execute("SELECT COUNT(*) FROM authority_grant_history WHERE grant_id=?", (child.resource["grant_id"],)).fetchone()[0] == 2
            finally:
                await client.aclose()
            from agent_meta_runtime.adapters.store.authority import CreateGrantRequest, create_grant
            from agent_meta_runtime.adapters.store.uow import execute_command
            from agent_meta_runtime.domain.authority import Scope, ScopeTarget
            from agent_meta_runtime.domain.deadline import Deadline
            envelope = decode_command(canonical_json(make_envelope(env.realm, "unit.service-grant/v1", {})))
            seeded = execute_command(env.conn, envelope, create_grant(CreateGrantRequest(env.authority.authority_grant_id,
                "principal://service/01900000-0000-7000-8000-000000000001", frozenset({"task.execute"}),
                Scope(env.realm, (ScopeTarget("REALM_ALL"),)), delegable=False)), deadline=Deadline.after(5_000_000))
            before = counts(env)
            with pytest.raises(StableError) as error:
                await root.revoke_authority(realm_id=env.realm, actor_id=ACTOR, grant_id=seeded.receipt["grant_id"])
            assert error.value.code == ErrorCode.AUTHORITY_DENIED and business_unchanged(env, before)
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("method", ["CreatePrincipal", "Delegate", "Revoke"])
def test_old_minor_refuses_new_authority_method_before_payload_handling(tmp_path, method):
    async def scenario(env):
        reader, writer = await _raw_hello(env.socket_path, minor=3)()
        try:
            before = counts(env)
            request = t.RpcEnvelope(protocol_major=1, protocol_minor=3, request_id="old-authority",
                method="agent_meta.public.v1.Authority." + method, payload=pub.CommandRequest().SerializeToString())
            writer.write(encode_frame(request.SerializeToString()))
            await writer.drain()
            size = struct.unpack(">I", await reader.readexactly(4))[0]
            response = parse_envelope(await reader.readexactly(size))
            assert response.error.code == ErrorCode.CONTRACT_INCOMPATIBLE and counts(env) == before
        finally:
            writer.close()
            await writer.wait_closed()
    run_env(scenario, tmp_path)


@pytest.mark.parametrize("raw_json", ["{", "null", '{"realm_id":"realm://main","realm_id":"realm://main","targets":[{"type":"REALM_ALL"}]}'])
@pytest.mark.parametrize("dry_run", [False, True])
def test_cli_bad_scope_fails_before_any_client_call(raw_json, dry_run):
    args = ["--data-dir", "fixture", "authority", "delegate", "--subject", "principal://agent/" + new_uuid7(),
        "--permission", "task.submit", "--scope", raw_json]
    if dry_run:
        args.insert(2, "--dry-run")
    namespace = build_parser().parse_args(args)
    class NoCalls:
        def __getattr__(self, name):
            raise AssertionError("invalid arguments reached the client")
    async def scenario():
        with pytest.raises(StableError) as error:
            await cmd_authority(NoCalls(), namespace)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT
    asyncio.run(scenario())


@pytest.mark.parametrize("fields", [{"scope": []}, {"scope": [("realm_id", "realm://main"), ("targets", [{"type": "REALM_ALL"}])]},
    {"constraints": []}, {"constraints": False}, {"permissions": "task.submit"}, {"delegable": 1}])
def test_sdk_does_not_coerce_invalid_authority_containers_before_transport(fields):
    class NoRequests:
        async def call(self, *args, **kwargs):
            raise AssertionError("invalid delegation reached transport")
    async def scenario():
        client = AgentMetaClient(NoRequests())
        values = {"realm_id": "realm://main", "actor_id": ACTOR, "subject_id": "principal://agent/" + new_uuid7(),
            "permissions": ["task.submit"], "scope": {"realm_id": "realm://main", "targets": [{"type": "REALM_ALL"}]}, **fields}
        with pytest.raises(StableError) as error:
            await client.delegate_authority(**values)
        assert error.value.code == ErrorCode.INVALID_ARGUMENT
    asyncio.run(scenario())
