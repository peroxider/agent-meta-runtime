"""Actual SQLite admission -> certified process -> local TLS -> terminal.

Synthetic profile/usage only: these are internal assembly checks, not a public
profile, EffectIntent/Managed backend, captured R2 or live Provider proof.
"""

import asyncio
from dataclasses import replace
import json
import os
from types import SimpleNamespace

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.credentials import WindowsCredentialStore, InsecureDevCredentialStore
from agent_meta_runtime.adapters.crypto import Ed25519KeyPair
from agent_meta_runtime.adapters.provider_host import ProviderHostCalls
from agent_meta_runtime.adapters.provider_worker import ProviderWorkerController
from agent_meta_runtime.adapters.provider_worker_wire import ProviderWorkerBootstrap
from agent_meta_runtime.adapters.store import (RootBootstrapRequest, bootstrap_root, CreateGrantRequest,
    create_grant, RevokeGrantRequest, revoke_grant, load_task)
from agent_meta_runtime.adapters.store.connection import connect_store
from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
from agent_meta_runtime.adapters.store.provider_accounting import read_provider
from agent_meta_runtime.adapters.store.service_certificates import load_service_execution_trust
from agent_meta_runtime.adapters.store.task_snapshot import register_staged_artifact
from agent_meta_runtime.domain.authority import GrantConstraints, Scope, ScopeTarget
from agent_meta_runtime.domain.canonical import canonical_json, now_us
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.execution_tokens import issue_service_certificate
from agent_meta_runtime.domain.provider_accounting import ProviderReservation
from agent_meta_runtime.domain.semantics import TaskBudget
from agent_meta_runtime.ports.host_execution import HostCallValue
from agent_meta_runtime.ports.repositories import FactAppendRequest

from conftest import ACTOR, artifact_id
from test_execution_tokens import SERVICE
from test_provider_accounting import command
from test_provider_https import edge, SECRET
from test_semantic_tasks import _accept

CAPABILITY = "capability://fixture.model"
OPERATION = {"operation_id": "fixture.model", "effects": ["model.invoke"], "required_permissions": ["model.invoke"]}


@pytest.fixture
def provider_host(semantic_env, tmp_path, edge):
    conn, realm, composition, input_ref, surface_ref = semantic_env
    server, _, base, _, _, _, ca, _ = edge
    root, service = Ed25519KeyPair.generate(), Ed25519KeyPair.generate()
    epoch = conn.execute("SELECT epoch_id FROM realms").fetchone()[0]
    root_grant = command(conn, bootstrap_root(RootBootstrapRequest(realm, epoch, ACTOR,
        root.public_bytes_raw(), "a"*64)))["grant_id"]
    identity = canonical_json({"algorithm": "Ed25519", "public_key_hex": service.public_bytes_raw().hex()})
    conn.execute("INSERT INTO principals VALUES (?,?, 'SERVICE',?, 'ACTIVE',1)", (SERVICE, realm, identity))
    conn.commit()
    grant = command(conn, create_grant(CreateGrantRequest(root_grant, SERVICE, frozenset({"model.invoke"}),
        Scope(realm, [ScopeTarget("CAPABILITY", CAPABILITY)]), constraints=GrantConstraints(max_uses=1))))["grant_id"]
    cas = FilesystemCas(tmp_path)
    def read(connection, ref):
        size, manifest = connection.execute("SELECT size_bytes,manifest_json FROM artifacts WHERE artifact_id=?", (ref,)).fetchone()
        return cas.open_blob(json.loads(manifest)["storage_relpath"], ref.rsplit("/",1)[1], size)
    def host(connection=conn):
        return HostExecutionStore(connection, catalog=SimpleNamespace(cas=cas,read_artifact=lambda ref: read(connection,ref)),
            run_command=lambda fn: command(connection,fn), realm_id=realm, service_id=SERVICE)
    store = host()
    certificate = issue_service_certificate({"service_principal_id": SERVICE, "public_key": service.public_bytes_raw().hex(),
        "realm_id": realm, "epoch_id": epoch, "permissions": ["model.invoke"], "not_after": now_us()+86_400_000_000},
        root_principal_id=ACTOR, signer=root.sign)
    staged = store.stage(certificate)
    def initialize(txn):
        register_staged_artifact(txn, staged, kind="authority_certificate")
        for entity, identity, event, payload in (
            ("runtime",realm,"runtime_initialized",{"service_principal_id":SERVICE,"service_certificate_artifact_id":staged["artifact_id"]}),
            ("harness","harness://fixture","harness_activated",{"phase":"requested","composition_id":composition,"grant_ids":[grant]})):
            txn.append_fact(FactAppendRequest(entity_type=entity,entity_id=identity,event_type=event,schema_version=1,
                payload=payload,actor_id=ACTOR,occurred_at_us=txn.recorded_at_us))
        return {}
    command(conn,initialize)
    accepted = _accept(conn,realm,composition,input_ref,surface_ref,budget=TaskBudget(max_cost_microunits=100),deadline_at_us=now_us()+30_000_000)
    record = load_task(conn,accepted["task_id"])
    task = SimpleNamespace(**{name:getattr(record,name) for name in (
        "task_id","root_action_id","realm_id","actor_id","serving_composition_id","deadline_at_us")}, loop_policy_content=b"{}")
    credentials = (WindowsCredentialStore if os.name == "nt" else InsecureDevCredentialStore)(tmp_path/'credentials',create=True)
    material = bytearray(SECRET)
    try:
        handle = credentials.create(material,purpose="provider")
    finally:
        material[:] = b'\0'*len(material)
    request = replace(base,request_id=task.task_id+'/invocation/0',credential_handle=handle,
        policy=replace(base.policy,host='localhost',networks=('127.0.0.1/32','::1/128')),
        timeout_us=5_000_000,deadline_at_us=task.deadline_at_us)
    boot = ProviderWorkerBootstrap(ACTOR,root.public_bytes_raw(),realm,epoch,certificate,'prototype',str(credentials.root),credentials.profile,ca)
    trust = load_service_execution_trust(conn,cas,realm_id=realm,now_us=now_us())
    reservation = ProviderReservation(artifact_id('synthetic-profile'),artifact_id('synthetic-price'),artifact_id('synthetic-tokenizer'),
        request.scope_hash,10,request.required_ceiling['output_tokens'],60)
    invocation = store.reserve(task,ordinal=0,kind="MODEL",capability_id=CAPABILITY,operation=OPERATION,content=b'{}',provider=reservation)["invocation_id"]
    return SimpleNamespace(conn=conn,store=store,host=host,task=task,server=server,request=request,boot=boot,trust=trust,
        signer=service.sign,epoch=epoch,invocation=invocation,grant=grant,root=tmp_path,reservation=reservation)


def normalized(raw):
    assert raw == b'{"reply":"synthetic"}'
    return HostCallValue(content=b'{"normalized":"synthetic"}',usage={"input_tokens":10,"output_tokens":5,"cost_microunits":25})


def state(case, connection=None):
    connection = connection or case.conn
    raw = connection.execute("SELECT backend_ref_json FROM invocations WHERE invocation_id=?", (case.invocation,)).fetchone()[0]
    return read_provider(connection,case.invocation,json.loads(raw))


async def invoke(case, worker, **overrides):
    edge = ProviderHostCalls(case.store,worker=worker,trust=case.trust,epoch_id=case.epoch,signer=case.signer)
    return await edge.invoke(task=case.task,invocation_id=case.invocation,request=overrides.get('request',case.request),
        required_permissions={'model.invoke'},normalize=overrides.get('normalize',normalized))


def test_real_worker_requires_committed_authorization_before_sending_and_settles(provider_host):
    case = provider_host
    async def run():
        worker = ProviderWorkerController(case.boot)
        class Observed:
            session_id = worker.session_id
            async def run(self,request,**kwargs):
                assert not case.conn.in_transaction
                assert case.conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_dispatch_authorized'").fetchone()[0] == 1
                assert state(case)['settlement'] is None
                return await worker.run(request,**kwargs)
        try:
            value = await invoke(case,Observed())
            assert value.content == b'{"normalized":"synthetic"}' and len(case.server.seen) == 1
            assert state(case)['settlement']['liability_microunits'] == 25
            assert SECRET not in repr(case.conn.execute("SELECT payload_json FROM facts").fetchall()).encode()
            assert worker.observation(case.request.request_id)['exit_confirmed']
        finally:
            await worker.close()
    asyncio.run(run())


def test_response_then_commit_failure_cannot_resend_in_new_host_or_worker(provider_host):
    case = provider_host
    def fail_after_write(fn):
        def mutate(txn):
            fn(txn)
            raise StableError(code=ErrorCode.INTERNAL,message='injected terminal commit failure')
        return command(case.conn,mutate)
    async def run():
        worker = ProviderWorkerController(case.boot)
        case.store.run_command = fail_after_write
        try:
            with pytest.raises(StableError,match='injected'):
                await invoke(case,worker)
            assert len(case.server.seen) == 1 and state(case)['settlement'] is None
        finally:
            await worker.close()
        reopened = connect_store(case.root/'meta.db')
        fresh = ProviderWorkerController(case.boot)
        try:
            store = case.host(reopened)
            with pytest.raises(StableError) as caught:
                store.reserve(case.task,ordinal=0,kind='MODEL',capability_id=CAPABILITY,operation=OPERATION,content=b'{}',provider=case.reservation)
            assert caught.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            calls = ProviderHostCalls(store,worker=fresh,trust=case.trust,epoch_id=case.epoch,signer=case.signer)
            with pytest.raises(StableError) as caught:
                await calls.invoke(task=case.task,invocation_id=case.invocation,request=case.request,
                    required_permissions={'model.invoke'},normalize=normalized)
            assert caught.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            assert fresh.observation(case.request.request_id) is None and len(case.server.seen) == 1
        finally:
            await fresh.close()
            reopened.close()
    asyncio.run(run())


@pytest.mark.parametrize('mode',['disconnect','server_error'])
def test_accepted_uncertain_response_is_durably_unknown_without_retry(provider_host,mode):
    case = provider_host
    case.server.mode = mode
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            value = await invoke(case,worker)
            assert value.error_code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN and value.raise_error
            assert state(case)['settlement']['outcome'] == 'UNKNOWN'
            assert state(case)['settlement']['liability_microunits'] == 60
            with pytest.raises(StableError):
                await invoke(case,worker)
            assert len(case.server.seen) == 1
        finally:
            await worker.close()
    asyncio.run(run())


def test_revocation_between_reservation_and_dispatch_proves_not_sent(provider_host):
    case = provider_host
    command(case.conn,revoke_grant(RevokeGrantRequest(case.grant)))
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            with pytest.raises(StableError) as caught:
                await invoke(case,worker)
            assert caught.value.code == ErrorCode.AUTHORITY_DENIED
            assert state(case)['settlement']['outcome'] == 'NOT_SENT'
            assert state(case)['settlement']['liability_microunits'] == 0
            assert worker.observation(case.request.request_id) is None and not case.server.seen
        finally:
            await worker.close()
    asyncio.run(run())


def test_cancel_after_post_reaps_actual_worker_and_commits_unknown(provider_host):
    case = provider_host
    case.server.mode = 'hold'
    async def run():
        worker = ProviderWorkerController(case.boot)
        operation = asyncio.create_task(invoke(case,worker))
        try:
            async with asyncio.timeout(5):
                while not case.server.seen:
                    await asyncio.sleep(.01)
            operation.cancel()
            with pytest.raises(asyncio.CancelledError):
                await operation
            assert state(case)['settlement']['outcome'] == 'UNKNOWN'
            assert worker.observation(case.request.request_id)['exit_confirmed']
            assert len(case.server.seen) == 1
        finally:
            operation.cancel()
            await asyncio.gather(operation,return_exceptions=True)
            await worker.close()
    asyncio.run(run())


@pytest.mark.parametrize('change',['credential','body','deadline','request_id','signature'])
def test_dispatch_independently_refuses_substitution_before_any_native_request(provider_host,change):
    case = provider_host
    request = case.request
    if change == 'credential':
        request = replace(request,credential_handle='credential://a-different-item')
    elif change == 'body':
        body = json.loads(request.body); body['messages'][0]['content'] = 'different input'
        request = replace(request,body=canonical_json(body))
    elif change == 'deadline':
        request = replace(request,deadline_at_us=request.deadline_at_us+1)
    elif change == 'request_id':
        request = replace(request,request_id='different-attempt')
    else:
        case.signer = lambda _: b'\0'*64
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            with pytest.raises(StableError) as caught:
                await invoke(case,worker,request=request)
            assert caught.value.code == ErrorCode.AUTHORITY_DENIED
            assert not case.server.seen and worker.observation(request.request_id) is None
            assert state(case)['settlement']['outcome'] == 'NOT_SENT'
            assert case.conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_dispatch_authorized'").fetchone()[0] == 0
        finally:
            await worker.close()
    asyncio.run(run())


def test_second_malformed_dispatch_cannot_release_the_first_inflight_reservation(provider_host):
    case = provider_host
    case.server.mode = 'hold'
    async def run():
        worker = ProviderWorkerController(case.boot)
        first = asyncio.create_task(invoke(case,worker))
        try:
            async with asyncio.timeout(5):
                while not case.server.seen:
                    await asyncio.sleep(.01)
            changed = replace(case.request,credential_handle='credential://a-different-item')
            with pytest.raises(StableError) as caught:
                await invoke(case,worker,request=changed)
            assert caught.value.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN
            assert state(case)['settlement'] is None
            assert len(case.server.seen) == 1
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert state(case)['settlement']['liability_microunits'] == 60
        finally:
            first.cancel()
            await asyncio.gather(first,return_exceptions=True)
            await worker.close()
    asyncio.run(run())


@pytest.mark.parametrize('bad',['invalid','overrun'])
def test_normalization_failure_and_usage_overrun_never_deliver_a_success(provider_host,bad):
    case = provider_host
    def normalize(raw):
        if bad == 'invalid':
            raise ValueError('diagnostic must not persist '+SECRET.decode())
        return HostCallValue(content=b'{"normalized":"overrun"}',usage={'cost_microunits':101})
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            if bad == 'invalid':
                value = await invoke(case,worker,normalize=normalize)
                assert value.error_code == ErrorCode.INVALID_RESULT and value.content is None
                assert state(case)['settlement']['liability_microunits'] == 60
                assert state(case)['settlement']['usage']['cost_microunits'] is None
            else:
                with pytest.raises(StableError) as caught:
                    await invoke(case,worker,normalize=normalize)
                assert caught.value.code == ErrorCode.RESOURCE_EXHAUSTED
                assert state(case)['settlement']['liability_microunits'] == 101
                assert state(case)['settlement']['overrun']
            assert len(case.server.seen) == 1
            assert SECRET not in repr(case.conn.execute('SELECT payload_json FROM facts').fetchall()).encode()
        finally:
            await worker.close()
    asyncio.run(run())


def test_confirmed_terminal_replays_from_database_with_no_new_native_session(provider_host):
    case = provider_host
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            value = await invoke(case,worker)
        finally:
            await worker.close()
        reopened = connect_store(case.root/'meta.db')
        try:
            store = case.host(reopened)
            before = reopened.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0]
            replay = store.reserve(case.task,ordinal=0,kind='MODEL',capability_id=CAPABILITY,operation=OPERATION,
                content=b'{}',provider=case.reservation)
            assert replay['replay'] and store.read_artifact(replay['output_artifact_id']) == value.content
            assert reopened.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0] == before
            assert len(case.server.seen) == 1
        finally:
            reopened.close()
    asyncio.run(run())


def test_dispatch_fact_prevents_deleting_the_volatile_journal_marker(provider_host):
    case = provider_host
    async def run():
        worker = ProviderWorkerController(case.boot)
        try:
            await invoke(case,worker)
            raw = json.loads(case.conn.execute('SELECT backend_ref_json FROM invocations WHERE invocation_id=?',(case.invocation,)).fetchone()[0])
            del raw['provider_dispatch']
            case.conn.execute('UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?',(canonical_json(raw),case.invocation))
            case.conn.commit()
            with pytest.raises(StableError) as caught:
                case.store.reserve(case.task,ordinal=0,kind='MODEL',capability_id=CAPABILITY,operation=OPERATION,content=b'{}',provider=case.reservation)
            assert caught.value.code == ErrorCode.INTEGRITY_ERROR
            assert len(case.server.seen) == 1
        finally:
            await worker.close()
    asyncio.run(run())
