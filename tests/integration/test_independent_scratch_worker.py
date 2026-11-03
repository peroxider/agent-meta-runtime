"""Real independent kernel profile; optional dependencies must be installed."""
import asyncio
import os
from pathlib import Path
import json
import queue
import subprocess
import sys
import threading
import time

import pytest

from agent_meta_runtime.adapters.scratch_worker import ScratchWorker
from agent_meta_runtime.adapters.owned_worker import WorkerProcessLifetime
from agent_meta_runtime.sdk import StableError


def worker(tmp_path, **options):
    return ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'kernel',**options)


def test_independent_kernel_retains_cells_and_never_inherits_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('ANTHROPIC_AUTH_TOKEN','SCRATCH_PARENT_CREDENTIAL_CANARY')
    async def run():
        session = worker(tmp_path)
        await session.start()
        try:
            assert session.pid!=os.getpid() and session.state=='ACTIVE'
            first = await session.execute('value=41\nprint(value+1)')
            second = await session.execute("import os\nprint(value)\nprint('ANTHROPIC_AUTH_TOKEN' in os.environ)")
            assert first.stdout.strip()=='42' and second.stdout.strip()=='41\nFalse'
            assert first.ordinal==1 and second.ordinal==2
            assert first.error_type is second.error_type is None
        finally:
            await session.close()
        assert session.state=='CLOSED'
        assert not (session.workspace/'kernel.json').exists()
    asyncio.run(run())


def test_each_output_channel_is_bounded_before_transport_publication(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        try:
            result = await session.execute("import sys\nfrom IPython.display import display\nprint('x'*1200000)\nprint('y'*1200000,file=sys.stderr)\ndisplay({'text/plain':'z'*1200000},raw=True)")
            assert result.error_type is None
            assert len(result.stdout.encode())<=1048576 and len(result.stderr.encode())<=1048576
            assert sum(map(len,result.displays))<=1048576
            assert result.stdout_truncated and result.stderr_truncated and result.display_truncated
        finally:
            await session.close()
    asyncio.run(run())


def test_exception_contains_type_but_never_raw_reason_or_traceback(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        try:
            result = await session.execute("raise ValueError('SCRATCH_EXCEPTION_SECRET_CANARY')")
            assert result.error_type=='ValueError'
            assert 'SCRATCH_EXCEPTION_SECRET_CANARY' not in result.stdout+result.stderr+str(result.displays)
        finally:
            await session.close()
    asyncio.run(run())


@pytest.mark.parametrize('source', ['!echo forbidden','%run forbidden.py','%%bash\necho forbidden'])
def test_policy_refusal_does_not_start_a_cell(tmp_path,source):
    async def run():
        session = await worker(tmp_path).start()
        try:
            with pytest.raises(StableError) as denied:
                await session.execute(source)
            assert denied.value.code=='INVALID_ARGUMENT' and session.ordinal==0
        finally:
            await session.close()
    asyncio.run(run())


def test_idle_expiry_and_fresh_kernel_never_restore_heap(tmp_path):
    async def run():
        now = [0.0]
        session = await worker(tmp_path,idle_ttl_s=1,clock=lambda:now[0]).start()
        await session.execute('old_heap=42')
        now[0]=2
        with pytest.raises(StableError):
            await session.execute('print(old_heap)')
        assert session.state=='LOST'
        fresh = await ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'fresh').start()
        try:
            result = await fresh.execute("print('old_heap' in globals())")
            assert result.stdout.strip()=='False' and fresh.pid!=session.pid
        finally:
            await fresh.close()
    asyncio.run(run())


def test_interrupting_a_busy_cell_returns_a_known_terminal_without_reexecution(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        try:
            pending = asyncio.create_task(session.execute('while True: pass',timeout_s=30))
            await asyncio.sleep(.2)
            await session.interrupt()
            result = await pending
            assert session.state=='ACTIVE' and result.error_type=='KeyboardInterrupt' and result.ordinal==1
            resumed = await session.execute('print(42)')
            assert resumed.stdout.strip()=='42' and resumed.ordinal==2
        finally:
            await session.close(force=True)
    asyncio.run(run())


def test_never_started_worker_close_cannot_remove_an_existing_file(tmp_path):
    target = tmp_path/'existing'
    target.mkdir()
    key = target/'kernel.json'
    key.write_text('owned by another session')
    session = ScratchWorker(workspace_root=tmp_path,workspace=target)
    asyncio.run(session.close())
    assert key.read_text()=='owned by another session'


def test_self_terminated_kernel_is_unknown_without_waiting_for_cell_deadline(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        try:
            with pytest.raises(StableError) as unknown:
                await asyncio.wait_for(session.execute('import os\nos._exit(37)'),8)
            assert unknown.value.code=='EXTERNAL_EFFECT_UNKNOWN'
            assert session.state=='LOST' and session.ordinal==1
            with pytest.raises(StableError) as expired:
                await session.execute('print(42)')
            assert expired.value.code=='FAILED_PRECONDITION' and session.ordinal==1
        finally:
            await session.close(force=True)
    asyncio.run(run())


SPAWN_DESCENDANT = """import subprocess,sys
child = subprocess.Popen([sys.executable,'-I','-u','-c',
    'import os,time; print(os.getpid(),flush=True); time.sleep(60)'],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
print(child.stdout.readline().decode('ascii').strip())
"""


def test_forced_release_kills_actual_kernel_and_descendant(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        witnesses = []
        try:
            result = await session.execute(SPAWN_DESCENDANT)
            witnesses = [WorkerProcessLifetime(pid) for pid in (session.pid,int(result.stdout.strip()))]
            assert all(not witness.wait(0) for witness in witnesses)
            pending = asyncio.create_task(session.execute('while True: pass'))
            await asyncio.sleep(.2)
            await session.close(force=True)
            with pytest.raises((StableError,asyncio.CancelledError)):
                await pending
            assert session.state=='LOST'
            assert all(await asyncio.gather(*(asyncio.to_thread(witness.wait,5) for witness in witnesses)))
        finally:
            await session.close(force=True)
            for witness in witnesses:
                witness.close()
    asyncio.run(run())


def test_abrupt_owner_death_kills_kernel_and_descendant_without_python_cleanup(tmp_path):
    owner_code = '''
import asyncio,json,os,sys
from pathlib import Path
from agent_meta_runtime.adapters.scratch_worker import ScratchWorker
async def main():
    root = Path(sys.argv[1])
    session = await ScratchWorker(workspace_root=root,workspace=root/'kernel').start()
    result = await session.execute(SPAWN_DESCENDANT)
    print(json.dumps({'kernel_pid':session.pid,'child_pid':int(result.stdout.strip())}),flush=True)
    sys.stdin.buffer.read(1)
    os._exit(91)
asyncio.run(main())
'''.replace('SPAWN_DESCENDANT',repr(SPAWN_DESCENDANT))
    environment = {name:os.environ[name] for name in ('SystemRoot','TEMP','TMP','PATH') if name in os.environ}
    owner = subprocess.Popen([sys.executable,'-I','-u','-c',owner_code,str(tmp_path)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=environment,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    messages = queue.Queue()
    threading.Thread(target=lambda:messages.put(owner.stdout.readline()),daemon=True).start()
    witnesses = []
    try:
        observation = json.loads(messages.get(timeout=25))
        witnesses = [WorkerProcessLifetime(observation[name]) for name in ('kernel_pid','child_pid')]
        assert all(not witness.wait(0) for witness in witnesses)
        owner.stdin.write(b'!')
        owner.stdin.flush()
        assert owner.wait(timeout=8)==91
        assert all(witness.wait(5) for witness in witnesses)
    finally:
        if owner.poll() is None:
            owner.kill()
        owner.wait(timeout=8)
        owner.stdin.close()
        owner.stdout.close()
        for witness in witnesses:
            witness.close()


@pytest.mark.parametrize('source', ['\ud800','x'*1048577])
def test_malformed_source_is_refused_before_start(source,tmp_path):
    session = worker(tmp_path)
    async def run():
        with pytest.raises(StableError) as invalid:
            await session.execute(source)
        assert invalid.value.code=='INVALID_ARGUMENT' and session.state=='NEW'
    asyncio.run(run())


@pytest.mark.parametrize('value', [True,float('nan'),float('inf'),-1,14401])
def test_invalid_lifetime_configuration_is_refused(value,tmp_path):
    with pytest.raises(ValueError):
        worker(tmp_path,wall_ttl_s=value)


def test_ignored_interrupt_forces_native_cleanup_after_five_seconds(tmp_path):
    async def run():
        session = await worker(tmp_path).start()
        witness = WorkerProcessLifetime(session.pid)
        try:
            pending = asyncio.create_task(session.execute('import signal\nsignal.signal(signal.SIGINT,signal.SIG_IGN)\nwhile True: pass'))
            await asyncio.sleep(.2)
            started = time.monotonic()
            await session.interrupt()
            assert 4.5<=time.monotonic()-started<8
            with pytest.raises((StableError,asyncio.CancelledError)):
                await pending
            assert session.state=='LOST' and witness.wait(3)
        finally:
            await session.close(force=True)
            witness.close()
    asyncio.run(run())


@pytest.mark.parametrize('busy', [False,True])
def test_lifetime_expiry_reaps_worker_without_another_caller_request(tmp_path,busy):
    async def run():
        options = {'wall_ttl_s':.5} if busy else {'idle_ttl_s':.2}
        session = await worker(tmp_path,**options).start()
        witness = WorkerProcessLifetime(session.pid)
        pending = None
        try:
            if busy:
                pending = asyncio.create_task(session.execute('while True: pass'))
            async with asyncio.timeout(5):
                while session.state!='LOST':
                    await asyncio.sleep(.05)
            assert witness.wait(0)
            if pending is not None:
                with pytest.raises((StableError,asyncio.CancelledError)):
                    await pending
            assert session._lifetime_task.done()
        finally:
            await session.close(force=True)
            witness.close()
    asyncio.run(run())
