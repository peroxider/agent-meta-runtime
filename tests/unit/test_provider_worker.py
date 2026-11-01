"""Actual fixed worker process/TLS/credential boundary; no live Provider."""
import asyncio
from dataclasses import replace
import json
import os
import secrets
import subprocess
import sys
import signal

import pytest

from agent_meta_runtime.adapters.credentials import WindowsCredentialStore, InsecureDevCredentialStore
from agent_meta_runtime.adapters.provider_worker import ProviderWorkerController, ProviderWorkerInterrupted
from agent_meta_runtime.adapters.provider_worker_wire import (ProviderWorkerBootstrap, command,
    parse_command, parse_outcome, read_frame, write_frame, document, MAX_FRAME_BYTES, outcome_document)
from agent_meta_runtime.adapters.owned_worker import OwnedWindowsJob, WorkerProcessLifetime
from agent_meta_runtime.domain.canonical import canonical_json, now_us
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.provider_transport import ProviderHttpOutcome
from test_execution_tokens import ROOT, EPOCH
from test_provider_https import edge, SECRET


@pytest.fixture
def worker_case(edge, tmp_path):
    server, _transport, request, chain, _credentials, _dns, ca, _resolve = edge
    store = (WindowsCredentialStore if os.name == 'nt' else InsecureDevCredentialStore)(tmp_path/'credentials', create=True)
    material = bytearray(SECRET)
    try:
        handle = store.create(material, purpose='provider')
    finally:
        material[:] = b'\0' * len(material)
    request = replace(request, credential_handle=handle, timeout_us=5_000_000, deadline_at_us=now_us()+8_000_000,
        policy=replace(request.policy, host='localhost', networks=('127.0.0.1/32','::1/128')))
    boot = ProviderWorkerBootstrap(ROOT, chain.root.public_bytes_raw(), 'realm://main', EPOCH,
        chain.raw_certificate, chain.binding.backend_session_id, str(store.root), store.profile, ca)
    return server, request, chain, boot


def authorized(request, chain, session_id=None):
    current = now_us()
    binding = replace(chain.binding, backend_session_id=session_id or chain.binding.backend_session_id, target_scope_hash=request.scope_hash,
        resource_ceiling=request.required_ceiling, deadline_at_us=request.deadline_at_us)
    authorization = chain.token(backend_session_id=binding.backend_session_id, target_scope_hash=request.scope_hash, resource_ceiling=request.required_ceiling,
        issued_at_us=current, expires_at_us=min(current+60_000_000,request.deadline_at_us),
        token_id=new_uuid7(), nonce=secrets.token_hex(16))
    return dict(authorization=authorization, binding=binding)


async def accepted(server, controller, request):
    async with asyncio.timeout(5):
        while not server.seen:
            await asyncio.sleep(.01)
    value = controller.observation(request.request_id)
    assert value['worker_pid'] and value['request_started']
    return value


def test_instantiated_worker_uses_protected_handle_without_secret_in_control_or_environment(worker_case, monkeypatch):
    server, request, chain, boot = worker_case
    auth = authorized(request, chain)
    raw = canonical_json(command(boot, request, **auth))
    assert SECRET not in raw and SECRET.hex().encode() not in raw
    monkeypatch.setenv('ANTHROPIC_AUTH_TOKEN', 'synthetic-environment-value-must-not-be-used')
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    async def run():
        controller = ProviderWorkerController(boot)
        auth = authorized(request, chain, controller.session_id)
        try:
            outcome = await controller.run(request, **auth)
            assert outcome.state == 'RESPONSE' and outcome.content == b'{"reply":"synthetic"}'
            observed = controller.observation(request.request_id)
            assert observed['worker_pid'] != os.getpid() and observed['exit_confirmed'] and observed['terminal']
            assert await controller.run(request, **auth) == outcome
            assert len(server.seen) == 1 and server.seen[0][1] == 'Bearer '+SECRET.decode()
            assert SECRET not in repr(outcome).encode()
        finally:
            await controller.close()
    asyncio.run(run())


def test_worker_invalid_authorization_never_spawns_or_resolves_a_credential(worker_case):
    server, request, chain, boot = worker_case
    async def run():
        controller = ProviderWorkerController(boot)
        auth = authorized(request, chain, controller.session_id)
        body = json.loads(auth['authorization']); body['signature'] = '00'*64
        auth['authorization'] = canonical_json(body)
        try:
            with pytest.raises(StableError) as error:
                await controller.run(request, **auth)
            assert error.value.code == ErrorCode.AUTHORITY_DENIED
            assert controller.observation(request.request_id) is None and not server.seen
        finally:
            await controller.close()
    asyncio.run(run())


@pytest.mark.parametrize('mode', ['disconnect','truncated','server_error','escaped_echo'])
def test_worker_retains_terminal_or_unknown_outcome_without_another_process_or_send(worker_case, mode):
    server, request, chain, boot = worker_case
    server.mode = mode
    async def run():
        controller = ProviderWorkerController(boot)
        auth = authorized(request, chain, controller.session_id)
        try:
            result = await controller.run(request, **auth)
            assert result.state == ('RESPONSE' if mode == 'escaped_echo' else 'UNKNOWN')
            original = controller.observation(request.request_id)
            assert original['exit_confirmed']
            assert await controller.run(request, **auth) == result
            assert controller.observation(request.request_id) == original and len(server.seen) == 1
        finally:
            await controller.close()
    asyncio.run(run())


def test_cancel_after_request_reaps_actual_worker_and_never_reissues_unknown_call(worker_case):
    server, request, chain, boot = worker_case
    server.mode = 'hold'
    async def run():
        controller = ProviderWorkerController(boot)
        auth = authorized(request, chain, controller.session_id)
        try:
            task = asyncio.create_task(controller.run(request, **auth))
            await accepted(server, controller, request)
            task.cancel()
            with pytest.raises(ProviderWorkerInterrupted) as error:
                await task
            assert error.value.outcome.state == 'UNKNOWN'
            assert controller.observation(request.request_id)['exit_confirmed']
            assert await controller.run(request, **auth) == error.value.outcome
            assert len(server.seen) == 1
        finally:
            await controller.close()
    asyncio.run(run())


def test_absolute_deadline_includes_queueing_and_worker_startup(worker_case):
    server, request, chain, boot = worker_case
    server.mode = 'hold'
    async def run():
        controller = ProviderWorkerController(boot, maximum_processes=1)
        owner = asyncio.create_task(controller.run(request, **authorized(request, chain, controller.session_id)))
        try:
            await accepted(server, controller, request)
            queued = replace(request, request_id='queued-provider-call', deadline_at_us=now_us()+100_000)
            outcome = await controller.run(queued, **authorized(queued, chain, controller.session_id))
            assert outcome.state == 'NOT_SENT'
            assert controller.observation(queued.request_id)['launcher_pid'] is None
            assert len(server.seen) == 1
        finally:
            owner.cancel()
            await asyncio.gather(owner,return_exceptions=True)
            await controller.close()
    asyncio.run(run())


def test_concurrent_worker_waiters_observe_one_process_and_one_send(worker_case):
    server, request, chain, boot = worker_case
    async def run():
        controller = ProviderWorkerController(boot)
        auth = authorized(request, chain, controller.session_id)
        try:
            outcomes = await asyncio.gather(*(controller.run(request, **auth) for _ in range(4)))
            assert outcomes[0].content is not None and all(r == outcomes[0] for r in outcomes)
            assert len(server.seen) == 1 and controller.observation(request.request_id)['exit_confirmed']
        finally:
            await controller.close()
    asyncio.run(run())


def test_repeated_cancellation_waits_for_actual_worker_cleanup(worker_case):
    server, request, chain, boot = worker_case
    server.mode = 'hold'
    async def run():
        controller = ProviderWorkerController(boot)
        try:
            task = asyncio.create_task(controller.run(request, **authorized(request, chain, controller.session_id)))
            await accepted(server, controller, request)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(ProviderWorkerInterrupted) as error:
                await task
            assert error.value.outcome.state == 'UNKNOWN'
            assert controller.observation(request.request_id)['exit_confirmed'] and len(server.seen) == 1
        finally:
            await controller.close()
    asyncio.run(run())


def test_private_command_roundtrip_keeps_exact_scope_and_mutation_is_refused(worker_case):
    _server, request, chain, boot = worker_case
    auth = authorized(request, chain)
    value = command(boot, request, **auth)
    actual_boot, actual_request, actual_auth, actual_binding = parse_command(canonical_json(value))
    assert (actual_boot, actual_request, actual_auth, actual_binding) == (boot, request, auth['authorization'], auth['binding'])
    assert actual_request.scope_hash == request.scope_hash
    value['request']['body_sha256'] = '00'*32
    with pytest.raises(ValueError):
        parse_command(canonical_json(value))


@pytest.mark.parametrize('raw', [b'{"x":1,"x":1}', b'{}\n', b'[]', b'\xff', b' '*(MAX_FRAME_BYTES+1)])
def test_noncanonical_duplicate_or_oversized_control_documents_are_refused(raw):
    with pytest.raises((ValueError, UnicodeError)):
        document(raw)


def test_child_independently_rejects_bad_signature_before_opening_credential_root(worker_case, tmp_path):
    server, request, chain, boot = worker_case
    auth = authorized(request, chain)
    bad = json.loads(auth['authorization']); bad['signature'] = '00'*64
    payload = command(replace(boot, credential_root=str(tmp_path/'does-not-exist')), request,
        authorization=canonical_json(bad), binding=auth['binding'])
    async def run():
        job = OwnedWindowsJob() if os.name == 'nt' else None
        args = [sys.executable,'-I','-u','-m','agent_meta_runtime.adapters.provider_worker_process',
            '--parent-pid',str(os.getpid())]
        if job:
            args += ['--job-name',job.name]
        env = {k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        process = subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=env,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        async def exchange():
            ready = document(await asyncio.to_thread(read_frame,process.stdout))
            assert ready['status']=='READY' and (job is None or job.contains(ready['pid']))
            await asyncio.to_thread(write_frame,process.stdin,payload)
            process.stdin.close()
            outcome = parse_outcome(await asyncio.to_thread(read_frame,process.stdout))
            assert outcome.state=='NOT_SENT' and outcome.error_code==ErrorCode.AUTHORITY_DENIED
            assert not server.seen
        try:
            await asyncio.wait_for(exchange(),5)
        finally:
            if job:
                job.close()
            if process.poll() is None:
                process.kill()
            await asyncio.to_thread(process.wait,timeout=5)
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()
    asyncio.run(run())


def test_forced_controller_owner_loss_terminates_actual_http_worker(worker_case):
    server, request, chain, boot = worker_case
    server.mode = 'hold'
    request = replace(request, timeout_us=30_000_000, deadline_at_us=now_us()+40_000_000)
    payload = command(boot, request, **authorized(request, chain))
    supervisor = '''
import asyncio,os,sys
from dataclasses import replace
from agent_meta_runtime.adapters.provider_worker import ProviderWorkerController
from agent_meta_runtime.adapters.provider_worker_wire import read_frame,write_frame,parse_command
write_frame(sys.stdout.buffer,{'owner_pid':os.getpid()})
boot,request,token,binding=parse_command(read_frame(sys.stdin.buffer))
async def run():
    controller=ProviderWorkerController(boot)
    write_frame(sys.stdout.buffer,{'session_id':controller.session_id})
    updated,again,token,binding=parse_command(read_frame(sys.stdin.buffer))
    assert updated==replace(boot,session_id=controller.session_id) and again==request
    task=asyncio.create_task(controller.run(request,authorization=token,binding=binding))
    while True:
        observed=controller.observation(request.request_id)
        if observed and observed['worker_pid'] and observed['request_started']:
            break
        if task.done():
            task.result(); raise RuntimeError('worker did not send')
        await asyncio.sleep(.005)
    write_frame(sys.stdout.buffer,{'worker_pid':observed['worker_pid']})
    await task
asyncio.run(run())
'''
    async def run():
        env = {k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
        owner = subprocess.Popen([sys.executable,'-I','-u','-c',supervisor],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,close_fds=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        owner_ref = worker_ref = killer = None
        try:
            initial = document(await asyncio.wait_for(asyncio.to_thread(read_frame,owner.stdout),5))
            owner_pid = initial['owner_pid']
            owner_ref = WorkerProcessLifetime(owner_pid)
            if os.name == 'nt':
                from test_owned_worker_windows import ProcessWitness
                killer = ProcessWitness(owner_pid)
            await asyncio.to_thread(write_frame,owner.stdin,payload)
            session = document(await asyncio.wait_for(asyncio.to_thread(read_frame,owner.stdout),5))
            actual_boot = replace(boot,session_id=session['session_id'])
            actual_payload = command(actual_boot,request,**authorized(request,chain,session['session_id']))
            await asyncio.to_thread(write_frame,owner.stdin,actual_payload)
            info = document(await asyncio.wait_for(asyncio.to_thread(read_frame,owner.stdout),5))
            worker_ref = WorkerProcessLifetime(info['worker_pid'])
            async with asyncio.timeout(5):
                while not server.seen:
                    await asyncio.sleep(.01)
            assert not worker_ref.wait(0)
            if killer:
                killer.kill()
            else:
                os.kill(owner_pid,signal.SIGKILL)
            assert await asyncio.to_thread(owner_ref.wait,3)
            assert await asyncio.to_thread(worker_ref.wait,3)
            assert len(server.seen)==1
        finally:
            if owner_ref is not None and not owner_ref.wait(0):
                if killer:
                    killer.kill()
                else:
                    os.kill(owner_pid,signal.SIGKILL)
            if owner.poll() is None:
                owner.kill()
            await asyncio.to_thread(owner.wait,timeout=5)
            owner.stdin.close(); owner.stdout.close()
            if owner_ref:
                owner_ref.close()
            if worker_ref:
                worker_ref.close()
            if killer:
                killer.close()
    asyncio.run(run())


def test_new_controller_session_rejects_old_signed_request_instead_of_restoring_cache(worker_case):
    server, request, chain, boot = worker_case
    async def run():
        first = ProviderWorkerController(boot)
        auth = authorized(request,chain,first.session_id)
        try:
            assert (await first.run(request,**auth)).content is not None
        finally:
            await first.close()
        second = ProviderWorkerController(boot)
        try:
            assert second.session_id != first.session_id
            with pytest.raises(StableError) as error:
                await second.run(request,**auth)
            assert error.value.code == ErrorCode.AUTHORITY_DENIED
            assert second.observation(request.request_id) is None and len(server.seen)==1
        finally:
            await second.close()
    asyncio.run(run())


@pytest.mark.parametrize('field,value', [('request_id','different-request'),('request_scope_hash','00'*32)])
def test_worker_result_cannot_be_substituted_for_another_request_or_scope(field,value):
    result = outcome_document(ProviderHttpOutcome('RESPONSE',content=b'{}'),request_id='call-1',scope_hash='11'*32)
    result[field] = value
    with pytest.raises(ValueError):
        parse_outcome(canonical_json(result),expected_request_id='call-1',expected_scope_hash='11'*32)


def test_worker_without_absolute_deadline_fails_before_spawning(worker_case):
    server, request, chain, boot = worker_case
    request = replace(request,deadline_at_us=None)
    async def run():
        controller = ProviderWorkerController(boot)
        try:
            binding = replace(chain.binding,backend_session_id=controller.session_id,
                target_scope_hash=request.scope_hash,resource_ceiling=request.required_ceiling)
            current=now_us()
            token=chain.token(backend_session_id=controller.session_id,target_scope_hash=request.scope_hash,
                resource_ceiling=request.required_ceiling,issued_at_us=current,expires_at_us=current+60_000_000)
            with pytest.raises(StableError) as error:
                await controller.run(request,authorization=token,binding=binding)
            assert error.value.code==ErrorCode.FAILED_PRECONDITION
            assert controller.observation(request.request_id) is None and not server.seen
        finally:
            await controller.close()
    asyncio.run(run())


def test_worker_deadline_after_send_never_delivers_a_late_terminal_to_dispatch(worker_case):
    server, request, chain, boot = worker_case
    server.mode='hold'
    request=replace(request,deadline_at_us=now_us()+1_000_000)
    async def run():
        controller=ProviderWorkerController(boot)
        auth=authorized(request,chain,controller.session_id)
        try:
            task=asyncio.create_task(controller.run(request,**auth))
            await accepted(server,controller,request)
            result=await task
            assert result.state=='UNKNOWN' and result.content is None
            assert controller.observation(request.request_id)['exit_confirmed']
            server.release.set()  # upstream work can finish after local cancellation
            assert len(server.seen)==1
        finally:
            await controller.close()
    asyncio.run(run())
