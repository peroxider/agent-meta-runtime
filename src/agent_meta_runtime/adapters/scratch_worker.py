"""Owned independent IPython process for explicitly trusted exploration.

No admission, storage commit, credential or native handle crosses into package
code. The public Host integration must supply those mechanisms separately.
"""
import ast
import asyncio
import inspect
import importlib.util
import math
import os
from pathlib import Path
from queue import Empty
import re
import secrets
import signal
import subprocess
import sys
import time

from ..domain.canonical import canonical_json, now_us
from ..domain.errors import ErrorCode, StableError
from ..domain.reflection import InspectBudget
from ..domain.scratch_worker import CellOutputBudget, MAX_CELL_BYTES, ScratchCellResult
from .owned_worker import OwnedWindowsJob, WorkerProcessLifetime
from .scratch_ipython import check_cell_source, IDLE_TTL_US, WALL_TTL_US
from .windows_security import secure_owner_only


def _fail(code, message):
    return StableError(code=code,message=message)


def _secure(path, directory=False):
    if path.is_symlink() or path.is_junction():
        raise OSError('Scratch path must not be a reparse point')
    if os.name=='nt':
        secure_owner_only(path)
    else:
        path.chmod(0o700 if directory else 0o600)


class ScratchWorker:
    """Serialized cells; cancellation is a separate, owned control operation."""
    def __init__(self, *, workspace_root: Path, workspace: Path, idle_ttl_s=IDLE_TTL_US/1e6,
            wall_ttl_s=WALL_TTL_US/1e6, clock=time.monotonic):
        if not Path(workspace_root).is_absolute() or not Path(workspace).is_absolute():
            raise ValueError('Scratch workspace paths must be absolute')
        if any(type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=maximum
                for value,maximum in ((idle_ttl_s,IDLE_TTL_US/1e6),(wall_ttl_s,WALL_TTL_US/1e6))):
            raise ValueError('Scratch TTL exceeds its fixed lifetime ceiling')
        self.root, self.workspace = Path(workspace_root), Path(workspace)
        self.clock, self.idle_ttl_s, self.wall_ttl_s = clock,idle_ttl_s,wall_ttl_s
        self.state = 'NEW'
        self.process = self.job = self.lifetime = self.owner_lifetime = self.client = None
        self.pid = None
        self.ordinal = 0
        self.confirmed_result = None
        self.created = self.last_activity = None
        self._pending = None
        self._lock = asyncio.Lock()
        self._closing = asyncio.Lock()
        self._created_workspace = False
        self._lifetime_task = None
        self._observing = False

    def _dependencies(self):
        if not all(importlib.util.find_spec(name) for name in ('ipykernel','jupyter_client','zmq')):
            raise _fail(ErrorCode.FEATURE_UNAVAILABLE,'independent Scratch dependencies are unavailable')
        import zmq
        from jupyter_client import AsyncKernelClient
        from jupyter_client.connect import write_connection_file
        if not zmq.has('curve'):
            raise _fail(ErrorCode.FEATURE_UNAVAILABLE,'encrypted Scratch transport is unavailable')
        return zmq,AsyncKernelClient,write_connection_file

    async def start(self, *, before_start=None):
        if self.state!='NEW':
            raise _fail(ErrorCode.FAILED_PRECONDITION,'Scratch worker has already been started')
        if os.name!='nt' and not (sys.platform.startswith('linux') and hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal')):
            raise _fail(ErrorCode.FEATURE_UNAVAILABLE,'Scratch process ownership is unavailable')
        zmq,Client,write_connection_file = self._dependencies()
        if self.root.is_symlink() or self.root.is_junction() or not self.root.is_dir():
            raise _fail(ErrorCode.FAILED_PRECONDITION,'Scratch workspace root is unavailable')
        resolved_root = self.root.resolve(strict=True)
        parent = self.workspace.parent.resolve(strict=True)
        if not parent.is_relative_to(resolved_root) or self.workspace.exists() or self.workspace.is_symlink() or self.workspace.is_junction():
            raise _fail(ErrorCode.FAILED_PRECONDITION,'Scratch workspace is not a new owned child')
        if before_start is not None:
            result = before_start()
            if result is not None:
                if inspect.iscoroutine(result):
                    result.close()
                raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch startup admission must be synchronous')
        self.workspace.mkdir(mode=0o700)
        self._created_workspace = True
        _secure(self.workspace,True)
        self.state = 'STARTING'
        try:
            public, secret = zmq.curve_keypair()
            connection = self.workspace/'kernel.json'
            write_connection_file(str(connection),ip='127.0.0.1',key=secrets.token_hex(32).encode(),signature_scheme='hmac-sha256',
                curve_publickey=public,curve_secretkey=secret)
            _secure(connection)
            self.client = Client(connection_file=str(connection))
            self.client.load_connection_file()
            self.job = OwnedWindowsJob(kind='scratch') if os.name=='nt' else None
            env = {'PATH':str(Path(sys.executable).parent),'PYTHONNOUSERSITE':'1','TZ':'UTC',
                'TEMP':str(self.workspace),'TMP':str(self.workspace),'TMPDIR':str(self.workspace)}
            if os.name=='nt':
                env['SystemRoot'] = os.environ['SystemRoot']
            arguments = [sys.executable,'-I','-m','agent_meta_runtime.adapters.scratch_kernel_process',
                '--parent-pid',str(os.getpid()),'--workspace',str(self.workspace),'--connection-file',str(connection)]
            if self.job is not None:
                arguments += ['--job-name',self.job.name]
            else:
                arguments += ['--supervisor']
            self.process = subprocess.Popen(arguments,cwd=self.workspace,env=env,stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0,
                start_new_session=os.name!='nt')
            self.owner_lifetime = WorkerProcessLifetime(self.process.pid)
            self.client.start_channels()
            await self._ready()
            # A fixed fresh-namespace probe, before any caller cell, verifies the
            # actual process/isolated policy. Its values never become live handles.
            metadata = "{'pid':os.getpid(),'group':os.getpgrp() if hasattr(os,'getpgrp') else 0,'isolated':sys.flags.isolated,'user_site':site.ENABLE_USER_SITE,'history':get_ipython().history_manager.enabled,'cache':get_ipython().cache_size,'profile':get_ipython().profile_dir.location,'line_magics':sorted(get_ipython().magics_manager.magics['line']),'cell_magics':sorted(get_ipython().magics_manager.magics['cell'])}"
            _, reply = await asyncio.wait_for(self._exchange('import os, sys, site',expressions={'status':metadata}),10)
            observation = reply['user_expressions']['status']
            if observation['status']!='ok':
                raise ValueError('Scratch worker policy probe failed')
            status = ast.literal_eval(observation['data']['text/plain'])
            if (type(status) is not dict or type(status.get('pid')) is not int or status['pid']==os.getpid()
                    or status.get('isolated')!=1 or status.get('user_site') is not False or status.get('history') is not False
                    or status.get('cache')!=0 or status.get('line_magics')!=['time','timeit','whos'] or status.get('cell_magics')!=[]
                    or not Path(status['profile']).resolve().is_relative_to(self.workspace.resolve())
                    or self.job is not None and not self.job.contains(status['pid'])
                    or self.job is None and status.get('group')!=self.process.pid):
                raise ValueError('Scratch worker policy differs')
            self.pid = status['pid']
            self.lifetime = WorkerProcessLifetime(self.pid)
            self.created = self.last_activity = self.clock()
            self.state = 'ACTIVE'
            self._lifetime_task = asyncio.create_task(self._watch_lifetime())
        except BaseException as error:
            await self.close(force=True)
            if isinstance(error,asyncio.CancelledError):
                raise
            raise _fail(ErrorCode.FEATURE_UNAVAILABLE,'independent Scratch worker could not start') from None
        return self

    async def _watch_lifetime(self):
        try:
            while self.state=='ACTIVE':
                now = self.clock()
                remaining = self.wall_ttl_s-(now-self.created)
                if self._pending is None and not self._observing:
                    remaining = min(remaining,self.idle_ttl_s-(now-self.last_activity))
                if remaining<=0 or self.lifetime.wait(0):
                    await self.close(force=True)
                    return
                await asyncio.sleep(min(.25,remaining))
        except asyncio.CancelledError:
            return

    async def _ready(self):
        end = asyncio.get_running_loop().time()+15
        requests = set()
        while asyncio.get_running_loop().time()<end:
            if self.process.poll() is not None:
                raise OSError('Scratch owner exited')
            request = self.client.kernel_info()
            requests.add(request)
            try:
                reply = await self.client.get_shell_msg(timeout=1)
            except Empty:
                continue
            if reply['header']['msg_type']!='kernel_info_reply' or reply.get('parent_header',{}).get('msg_id') not in requests:
                continue
            try:
                await self.client.get_iopub_msg(timeout=.5)
            except Empty:
                continue
            return
        raise TimeoutError('Scratch ready deadline exceeded')

    async def _exchange(self, source, *, expressions=None):
        request = self.client.execute(source,store_history=False,allow_stdin=False,stop_on_error=True,user_expressions=expressions or {})
        budget = CellOutputBudget()
        streams, displays = {'stdout':[],'stderr':[]}, []
        def require_process():
            lifetime = self.lifetime or self.owner_lifetime
            if lifetime is None or lifetime.wait(0):
                raise OSError('Scratch worker exited without a confirmed cell result')
        async def output():
            while True:
                require_process()
                try:
                    message = await self.client.get_iopub_msg(timeout=1)
                except Empty:
                    continue
                if message.get('parent_header',{}).get('msg_id')!=request:
                    continue
                kind, content = message['header']['msg_type'],message['content']
                if kind=='stream' and content.get('name') in streams:
                    streams[content['name']].append(budget.stream(content['name'],content['text']))
                elif kind in ('display_data','execute_result','update_display_data'):
                    bundle = budget.display(content)
                    if bundle is not None:
                        displays.append(canonical_json(bundle))
                elif kind=='status' and content.get('execution_state')=='idle':
                    return
        async def terminal():
            while True:
                require_process()
                try:
                    message = await self.client.get_shell_msg(timeout=1)
                except Empty:
                    continue
                if message.get('parent_header',{}).get('msg_id')==request and message['header']['msg_type']=='execute_reply':
                    return message['content']
        output_task, reply_task = asyncio.create_task(output()),asyncio.create_task(terminal())
        try:
            _, reply = await asyncio.gather(output_task,reply_task)
        finally:
            for task in (output_task,reply_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(output_task,reply_task,return_exceptions=True)
        flags = reply.get('scratch_output')
        if type(flags) is not dict or set(flags)!=set(budget.flags()) or any(type(value) is not bool for value in flags.values()):
            raise ValueError('Scratch output limit receipt is absent')
        flags = {name:flags[name] or value for name,value in budget.flags().items()}
        name = reply.get('ename') if reply.get('status')=='error' else None
        name = name if name is None or type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',name) else 'ExecutionError'
        result = ScratchCellResult(self.ordinal or 1,reply.get('execution_count',0),''.join(streams['stdout']),''.join(streams['stderr']),
            tuple(displays),**flags,error_type=name)
        self.confirmed_result = result
        return result,reply

    async def _active(self):
        if self.state!='ACTIVE':
            raise _fail(ErrorCode.FAILED_PRECONDITION,'Scratch worker is not active')
        if self.lifetime.wait(0) or self.clock()-self.created>=self.wall_ttl_s or self.clock()-self.last_activity>=self.idle_ttl_s:
            await self.close(force=True)
            raise _fail(ErrorCode.FAILED_PRECONDITION,'Scratch worker lifetime has expired')

    async def _observe(self,content):
        async with self._lock:
            await self._active()
            self.last_activity = self.clock()
            self._observing = True
            message = self.client.session.send(self.client.control_channel.socket,
                'scratch_observe_request',content=content)
            request = message['header']['msg_id']
            async def receive():
                while True:
                    if self.lifetime.wait(0):
                        raise OSError('Scratch worker exited during observation')
                    try:
                        reply = await self.client.get_control_msg(timeout=.5)
                    except Empty:
                        continue
                    if (reply.get('parent_header',{}).get('msg_id')==request
                            and reply['header']['msg_type']=='scratch_observe_reply'):
                        return reply['content']
            try:
                reply = await asyncio.wait_for(receive(),5)
                if type(reply) is not dict:
                    raise ValueError('invalid Scratch observation receipt')
                if set(reply)=={'error_code'} and reply['error_code'] in (
                        ErrorCode.NOT_FOUND,ErrorCode.HANDLE_EXPIRED,ErrorCode.INVALID_ARGUMENT,
                        ErrorCode.RESOURCE_EXHAUSTED,ErrorCode.FAILED_PRECONDITION):
                    raise _fail(reply['error_code'],'Scratch observation was refused')
                if set(reply)!={'result'} or type(reply['result']) is not dict:
                    raise ValueError('invalid Scratch observation receipt')
                result = dict(reply['result'])
                # The fixed startup probe is internal, outside caller cell order.
                if result.get('cell_ordinal')!=self.ordinal+1:
                    raise ValueError('Scratch observation cell identity differs')
                result['cell_ordinal'] = self.ordinal
                if content.get('operation')=='bindings':
                    for entry in result['bindings']:
                        for key in ('created_cell','last_changed_cell'):
                            if entry.get(key) is not None:
                                entry[key] -= 1
                encoded = canonical_json(result)
                if len(encoded)>1024*1024:
                    raise ValueError('Scratch observation exceeds its ceiling')
                return encoded
            except StableError:
                raise
            except asyncio.CancelledError:
                await self.close(force=True)
                raise
            except Exception:
                await self.close(force=True)
                raise _fail(ErrorCode.BACKEND_UNAVAILABLE,'Scratch inspection was not confirmed') from None
            finally:
                self._observing = False
                self.last_activity = self.clock()

    async def bindings(self):
        return await self._observe({'operation':'bindings'})

    async def safe_inspect(self,*,name=None,handle=None,budget=None):
        if (name is None)==(handle is None) or budget is not None and type(budget) is not InspectBudget:
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch inspection needs one binding or handle')
        if name is not None and (type(name) is not str or not 1<=len(name)<=128 or not name.isidentifier()):
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch inspection needs a binding identifier')
        if handle is not None and (type(handle) is not str or not 1<=len(handle)<=128):
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch inspection needs an observed handle')
        current = budget if budget is not None else InspectBudget()
        options = {field:getattr(current,field) for field in ('max_depth','max_items','max_bytes','max_ms')}
        return await self._observe({'operation':'inspect','budget':options,
            **({'name':name} if name is not None else {'handle':handle})})

    async def execute(self, source, *, timeout_s=30, before_submit=None, deadline_at_us=None):
        valid_source = type(source) is str and len(source)<=MAX_CELL_BYTES
        if valid_source:
            try:
                valid_source = len(source.encode('utf-8'))<=MAX_CELL_BYTES and not check_cell_source(source)
            except UnicodeError:
                valid_source = False
        if not valid_source:
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch source is unavailable or denied')
        if type(timeout_s) not in (int,float) or not 0<timeout_s<=30:
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch cell deadline must be at most 30 seconds')
        if deadline_at_us is not None and (type(deadline_at_us) is not int or not 0<=deadline_at_us<=2**53-1):
            raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch deadline must be an absolute integer timestamp')
        async with self._lock:
            await self._active()
            self.confirmed_result = None
            remaining = (deadline_at_us-now_us())/1e6 if deadline_at_us is not None else timeout_s
            if remaining<=0:
                raise _fail(ErrorCode.DEADLINE_EXCEEDED,'Scratch deadline expired before submission')
            if before_submit is not None:
                # Private Root hook: after waiting for the owner lock/liveness,
                # before accepting any cell. It must finish synchronously and
                # release its writer before the native exchange is scheduled.
                value = before_submit()
                if value is not None:
                    if inspect.iscoroutine(value):
                        value.close()
                    raise _fail(ErrorCode.INVALID_ARGUMENT,'Scratch admission hook must be synchronous and return None')
            if deadline_at_us is not None:
                remaining = (deadline_at_us-now_us())/1e6
                if remaining<=0:
                    raise _fail(ErrorCode.DEADLINE_EXCEEDED,'Scratch deadline expired during submission admission')
            self.ordinal += 1
            self.last_activity = self.clock()
            self._pending = asyncio.create_task(self._exchange(source))
            try:
                result,_ = await asyncio.wait_for(asyncio.shield(self._pending),min(timeout_s,remaining,self.wall_ttl_s-(self.clock()-self.created)))
                return result
            except asyncio.TimeoutError:
                await self.interrupt()
                raise _fail(ErrorCode.DEADLINE_EXCEEDED,'Scratch cell deadline exceeded') from None
            except asyncio.CancelledError:
                if not asyncio.current_task().cancelling() and self.state in ('CLOSING','LOST'):
                    raise _fail(ErrorCode.EXTERNAL_EFFECT_UNKNOWN,'Scratch worker was lost during execution') from None
                if self.state!='LOST':
                    await self.interrupt()
                raise
            except Exception:
                await self.close(force=True)
                raise _fail(ErrorCode.EXTERNAL_EFFECT_UNKNOWN,'Scratch cell has no confirmed result') from None
            finally:
                self._pending = None
                self.last_activity = self.clock()

    async def interrupt(self, *, grace_s=5):
        pending = self._pending
        if pending is None or pending.done():
            return self.state
        try:
            self.client.session.send(self.client.control_channel.socket,'interrupt_request',content={})
            await asyncio.wait_for(asyncio.shield(pending),min(5,grace_s))
        except (Exception,asyncio.CancelledError):
            await self.close(force=True)
        return self.state

    async def close(self, *, force=False):
        async with self._closing:
            if self.state in ('CLOSED','LOST'):
                return
            if self.state=='NEW':
                self.state = 'CLOSED'
                return
            forced = force or self._pending is not None and not self._pending.done()
            self.state = 'CLOSING'
            watcher = self._lifetime_task
            if watcher is not None and watcher is not asyncio.current_task():
                watcher.cancel()
                await asyncio.gather(watcher,return_exceptions=True)
            if not forced and self.client is not None and self.lifetime is not None:
                try:
                    request = self.client.shutdown(restart=False)
                    async def acknowledged():
                        while True:
                            message = await self.client.get_control_msg(timeout=1)
                            if (message.get('parent_header',{}).get('msg_id')==request
                                    and message['header']['msg_type']=='shutdown_reply'):
                                return message['content'].get('status')=='ok'
                    forced = not await asyncio.wait_for(acknowledged(),5)
                except Exception:
                    forced = True
            # Explicit release closes the native owner even after a confirmed
            # shutdown reply: ipykernel can still be in its atexit/thread join.
            # No live heap or descendants survive a successful release.
            if self.job is not None:
                self.job.close()
            elif self.owner_lifetime is not None and not self.owner_lifetime.wait(0):
                self.owner_lifetime.signal(signal.SIGTERM)
            if self.process is not None:
                try:
                    await asyncio.to_thread(self.process.wait,timeout=5)
                except subprocess.TimeoutExpired:
                    # The fixed group owner is retained by pidfd, so no raw PID
                    # is ever selected for an unrelated process/group kill.
                    if self.owner_lifetime is not None:
                        self.owner_lifetime.signal(signal.SIGKILL)
                    await asyncio.to_thread(self.process.wait,timeout=5)
            if self.lifetime is not None and not await asyncio.to_thread(self.lifetime.wait,5):
                raise OSError('Scratch kernel termination was not confirmed')
            if self._pending is not None and not self._pending.done():
                self._pending.cancel()
            if self.client is not None:
                self.client.stop_channels()
            for lifetime in (self.lifetime,self.owner_lifetime):
                if lifetime is not None:
                    lifetime.close()
            connection = self.workspace/'kernel.json'
            if (self._created_workspace and not self.root.is_symlink() and not self.root.is_junction()
                    and not self.workspace.is_symlink() and not self.workspace.is_junction()
                    and self.workspace.resolve().is_relative_to(self.root.resolve())
                    and connection.is_file() and not connection.is_symlink()):
                connection.unlink()
            self.state = 'LOST' if forced else 'CLOSED'
