"""Fixed independent IPKernelApp entrypoint; receives no Root/Provider secrets."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import threading
import subprocess
import signal

from ..domain.scratch_worker import CellOutputBudget
from ..domain.scratch_observation import ScratchObserver
from .owned_worker import establish_owner_lifetime


def _parent_id(parent):
    if type(parent) is not dict:
        return None
    header = parent.get('header',parent)
    return header.get('msg_id') if type(header) is dict else None


class KernelOutputGuard:
    def __init__(self):
        self.parent = None
        self.budget = CellOutputBudget()
        self.lock = threading.Lock()

    def begin(self, parent):
        with self.lock:
            self.parent = _parent_id(parent)
            self.budget = CellOutputBudget()

    def wrap(self, session):
        send = session.send
        def guarded(stream, msg_or_type, content=None, parent=None, *args, **kwargs):
            kind = msg_or_type if type(msg_or_type) is str else msg_or_type.get('header',{}).get('msg_type')
            if type(msg_or_type) is dict:
                content = msg_or_type.get('content',{})
                parent = msg_or_type.get('parent_header',parent)
            with self.lock:
                if kind in ('stream','display_data','update_display_data','execute_result','error'):
                    if self.parent is None or _parent_id(parent)!=self.parent:
                        return None
                    if kind == 'stream':
                        text = self.budget.stream(content.get('name'),content.get('text'))
                        if not text:
                            return None
                        content = {'name':content['name'],'text':text}
                    elif kind == 'error':
                        name = content.get('ename','ExecutionError')
                        name = name if type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',name) else 'ExecutionError'
                        content = {'ename':name,'evalue':'','traceback':[]}
                    else:
                        bundle = self.budget.display(content)
                        if bundle is None:
                            return None
                        content = bundle
                        # Scratch records immutable MIME snapshots, no live display handle.
                        kind = 'display_data'
                    kwargs['metadata'] = {}
                if kind == 'execute_reply':
                    content = dict(content)
                    content['payload'] = []
                    content['scratch_output'] = self.budget.flags()
                    if content.get('status') == 'error':
                        name = content.get('ename','ExecutionError')
                        name = name if type(name) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',name) else 'ExecutionError'
                        content.update(ename=name,evalue='',traceback=[],reason_hash=hashlib.sha256(name.encode()).hexdigest())
            return send(stream,kind,content,parent,*args,**kwargs)
        session.send = guarded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parent-pid',type=int,required=True)
    parser.add_argument('--job-name')
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--connection-file',type=Path,required=True)
    parser.add_argument('--supervisor',action='store_true')
    args = parser.parse_args()
    if args.supervisor:
        if not sys.platform.startswith('linux'):
            raise RuntimeError('Scratch group supervisor requires Linux')
        establish_owner_lifetime(parent_pid=args.parent_pid,group_supervisor=True)
        try:
            child = subprocess.Popen([sys.executable,'-I','-m',__spec__.name,'--parent-pid',str(os.getpid()),
                '--workspace',str(args.workspace),'--connection-file',str(args.connection_file)],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            child.wait()
        finally:
            os.killpg(os.getpid(),signal.SIGKILL)
        return
    establish_owner_lifetime(parent_pid=args.parent_pid,job_name=args.job_name)
    for name,relative in (('JUPYTER_RUNTIME_DIR','runtime'),('JUPYTER_DATA_DIR','jupyter-data'),('JUPYTER_CONFIG_DIR','jupyter-config')):
        directory = args.workspace / relative
        directory.mkdir(exist_ok=False)
        os.environ[name] = str(directory)
    profile_root = args.workspace / 'isolated-ipython'
    profile = profile_root / 'profile_scratch'
    profile.mkdir(parents=True,exist_ok=False)
    from traitlets.config import Config
    from ipykernel.kernelapp import IPKernelApp
    configuration = Config()
    configuration.HistoryManager.enabled = False
    configuration.HistoryManager.hist_file = ':memory:'
    configuration.InteractiveShell.cache_size = 0
    configuration.InteractiveShellApp.exec_PYTHONSTARTUP = False
    configuration.BaseIPythonApplication.ipython_dir = str(profile_root)
    configuration.BaseIPythonApplication.profile = 'scratch'
    configuration.ProfileDir.location = str(profile)
    configuration.IPKernelApp.connection_file = str(args.connection_file)

    class ScratchKernelApp(IPKernelApp):
        def load_config_file(self,*args,**kwargs):
            return None
        def init_extensions(self):
            return None
        def init_code(self):
            return None
        def init_shell(self):
            super().init_shell()
            self.shell.magics_manager.magics['line'] = {name:callback for name,callback in self.shell.magics_manager.magics['line'].items()
                if name in ('time','timeit','whos')}
            self.shell.magics_manager.magics['cell'] = {}

    sys.argv = [sys.argv[0]]
    application = ScratchKernelApp.instance(config=configuration)
    application.connection_dir = str(args.workspace/'runtime')
    application.initialize([])
    if application.curve_secretkey is None:
        raise RuntimeError('encrypted Scratch transport is required')
    guard = KernelOutputGuard()
    guard.wrap(application.session)
    observer = ScratchObserver()
    async def observe_request(stream,ident,parent):
        result = observer.request(application.shell.user_ns,parent['content'])
        application.session.send(stream,'scratch_observe_reply',content=result,parent=parent,ident=ident)
    application.kernel.control_handlers['scratch_observe_request'] = observe_request
    execute = application.kernel.do_execute
    async def guarded_execute(*args,**kwargs):
        guard.begin(application.kernel.get_parent())
        observer.busy = True
        from .scratch_binding_trace import BindingWriteTrace
        observer.begin_cell(application.shell.user_ns)
        tracker = BindingWriteTrace(application.shell.user_ns)
        try:
            with tracker:
                return await execute(*args,**kwargs)
        finally:
            observer.end_cell(application.shell.user_ns,tracker.writes,tracker.complete)
            observer.busy = False
    application.kernel.do_execute = guarded_execute
    if os.name == 'nt':
        # The fixed worker owns this cooperative interrupt hook. ipykernel's
        # default control interrupt is unsupported on Windows; its Windows
        # parent poller uses the same main-thread interrupt primitive.
        from _thread import interrupt_main
        application.kernel._send_interrupt_children = interrupt_main
    application.start()


if __name__ == '__main__':
    main()
