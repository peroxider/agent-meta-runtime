"""Actual independent kernel inspection; no eval cell or live-object transport."""
import asyncio
import json

import pytest

from agent_meta_runtime.adapters.scratch_worker import ScratchWorker
from agent_meta_runtime.domain.reflection import InspectBudget
from agent_meta_runtime.sdk import StableError


def test_kernel_inspection_never_runs_hooks_and_does_not_execute_another_cell(tmp_path):
    async def run():
        worker = await ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'kernel').start()
        try:
            result = await worker.execute('''
calls=[]
class Name(str):
    def __getitem__(self,key):
        calls.append('name slice')
        raise RuntimeError('NAME_SLICE_SECRET')
    def encode(self,*args,**kwargs):
        calls.append('name encode')
        raise RuntimeError('NAME_ENCODING_SECRET')
class Meta(type):
    def __getattribute__(self,name):
        calls.append(name)
        raise RuntimeError('META_SECRET')
    def __eq__(self,other):
        calls.append('eq')
        raise RuntimeError('EQ_SECRET')
class Value(metaclass=Meta):
    @property
    def __dict__(self):
        calls.append('dict')
        raise RuntimeError('DICT_SECRET')
    def __repr__(self):
        calls.append('repr')
        raise RuntimeError('REPR_SECRET')
type.__setattr__(Value,'__name__',Name('Value'))
value=Value()
''')
            assert result.error_type is None
            bindings = json.loads(await worker.bindings())
            value = next(entry for entry in bindings['bindings'] if entry['name']=='value')
            assert value['type_name']=='Value' and value['handle'].startswith('obs:')
            inspected = json.loads(await worker.safe_inspect(handle=value['handle']))
            assert inspected['cell_ordinal']==bindings['cell_ordinal']==worker.ordinal==1
            assert inspected['node']['kind']=='object' and inspected['node']['children']==[]
            assert 'SECRET' not in str(inspected)
            observed = await worker.execute('print(calls)')
            assert observed.stdout.strip()=='[]' and observed.ordinal==2
        finally:
            await worker.close()
    asyncio.run(run())


def test_kernel_handle_expires_after_deletion_gc_and_worker_replacement(tmp_path):
    async def run():
        worker = await ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'kernel').start()
        handle = None
        try:
            await worker.execute('class Value: pass\nvalue=Value()')
            bindings = json.loads(await worker.bindings())
            handle = next(entry['handle'] for entry in bindings['bindings'] if entry['name']=='value')
            await worker.execute('del value\nimport gc\ngc.collect()')
            with pytest.raises(StableError) as expired:
                await worker.safe_inspect(handle=handle)
            assert expired.value.code=='HANDLE_EXPIRED' and worker.state=='ACTIVE'
        finally:
            await worker.close()
        fresh = await ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'fresh').start()
        try:
            await fresh.execute('class Value: pass\nvalue=Value()')
            with pytest.raises(StableError) as expired:
                await fresh.safe_inspect(handle=handle)
            assert expired.value.code=='HANDLE_EXPIRED'
        finally:
            await fresh.close()
    asyncio.run(run())


def test_kernel_inspection_budget_is_global_and_invalid_names_do_not_execute(tmp_path):
    async def run():
        worker = await ScratchWorker(workspace_root=tmp_path,workspace=tmp_path/'kernel').start()
        try:
            await worker.execute("value=[['x'*1000]*100]*100")
            result = json.loads(await worker.safe_inspect(name='value',budget=InspectBudget(max_items=5,max_bytes=4096)))
            assert result['node']['truncated'] and result['node']['consumed']['items']<=5
            assert result['node']['consumed']['bytes']<=4096
            for name in ('value.__class__','print(42)'):
                with pytest.raises(StableError) as invalid:
                    await worker.safe_inspect(name=name)
                assert invalid.value.code=='INVALID_ARGUMENT' and worker.ordinal==1
        finally:
            await worker.close()
    asyncio.run(run())
