"""Actual Job containment/owner crash, including venv redirector child PIDs."""
import ctypes
from ctypes import wintypes
import json
import os
import queue
import subprocess
import sys
import threading

import pytest

from agent_meta_runtime.adapters.owned_worker import OwnedWindowsJob

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows owner Job proof')

CHILD = '''
import json,os,sys,time
from agent_meta_runtime.adapters.owned_worker import establish_owner_lifetime
establish_owner_lifetime(parent_pid=int(sys.argv[2]),job_name=sys.argv[1])
print(json.dumps({'pid':os.getpid()}),flush=True)
time.sleep(60)  # owner loss must kill this process, not merely close stdin
'''


def spawn(code, *args):
    environment = {k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP') if k in os.environ}
    return subprocess.Popen([sys.executable,'-I','-u','-c',code,*map(str,args)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env=environment,creationflags=subprocess.CREATE_NO_WINDOW,close_fds=True)


def read_ready(process):
    messages = queue.Queue()
    def read():
        messages.put(process.stdout.readline())
    threading.Thread(target=read,daemon=True).start()
    return json.loads(messages.get(timeout=8))


class ProcessWitness:
    def __init__(self,pid):
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        self.kernel.OpenProcess.restype=wintypes.HANDLE
        self.kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype=wintypes.DWORD
        self.kernel.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT]
        self.kernel.TerminateProcess.restype=wintypes.BOOL
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        self.handle=self.kernel.OpenProcess(0x100000|0x1000|1,False,pid)
        assert self.handle

    def terminated(self,timeout=0):
        return self.kernel.WaitForSingleObject(self.handle,timeout)==0

    def kill(self):
        assert self.kernel.TerminateProcess(self.handle,99)

    def close(self):
        self.kernel.CloseHandle(self.handle)


def reap(process):
    try:
        process.stdin.close()
    except OSError:
        pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    process.stdout.close()


def test_actual_worker_joins_job_before_input_and_dies_on_job_close():
    job=OwnedWindowsJob()
    process=spawn(CHILD,job.name,os.getpid())
    witness=None
    try:
        ready=read_ready(process)
        witness=ProcessWitness(ready['pid'])
        assert job.contains(ready['pid']) and not witness.terminated()
        # Popen.pid may belong to the venv redirector. Check the actual worker.
        job.close()
        assert witness.terminated(3000)
    finally:
        job.close()
        reap(process)
        if witness:
            witness.close()


def test_abrupt_owner_loss_closes_kernel_job_and_kills_actual_worker():
    supervisor_code = '''
import json,os,subprocess,sys
from agent_meta_runtime.adapters.owned_worker import OwnedWindowsJob
job=OwnedWindowsJob()
child=subprocess.Popen([sys.executable,'-I','-u','-c',CHILD,job.name,str(os.getpid())],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
    creationflags=subprocess.CREATE_NO_WINDOW,close_fds=True)
ready=json.loads(child.stdout.readline())
assert job.contains(ready['pid'])
print(json.dumps({'owner_pid':os.getpid(),'worker_pid':ready['pid']}),flush=True)
sys.stdin.buffer.read(1)
'''.replace('CHILD',repr(CHILD))
    owner=spawn(supervisor_code)
    owner_witness=worker_witness=None
    try:
        ready=read_ready(owner)
        owner_witness=ProcessWitness(ready['owner_pid'])
        worker_witness=ProcessWitness(ready['worker_pid'])
        assert not worker_witness.terminated()
        owner_witness.kill()  # no Python cleanup/finally in the owner
        assert owner_witness.terminated(3000)
        assert worker_witness.terminated(3000)
    finally:
        if owner_witness and not owner_witness.terminated():
            owner_witness.kill()
        reap(owner)
        if owner_witness:
            owner_witness.close()
        if worker_witness:
            if not worker_witness.terminated():
                worker_witness.kill()
            worker_witness.close()
