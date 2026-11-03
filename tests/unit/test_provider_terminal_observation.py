"""Actual transport -> atomic observation/settlement -> bounded public query."""
import asyncio
from dataclasses import replace
import json
import sqlite3

import pytest

from agent_meta_runtime.adapters.provider_worker import ProviderWorkerController
from agent_meta_runtime.adapters.store.connection import connect_store
from agent_meta_runtime.adapters.store.task_execution import task_execution
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode,StableError
from agent_meta_runtime.domain.provider_accounting import ProviderTerminalObservation
from test_provider_host import provider_host,invoke,state
from test_provider_https import edge


def test_actual_429_preserves_retry_hint_without_secret_body_retry_or_unknown_cost_as_zero(provider_host):
    case=provider_host; case.server.mode='rate'
    async def run():
        worker=ProviderWorkerController(case.boot)
        try:
            value=await invoke(case,worker)
            assert value.error_code==ErrorCode.RESOURCE_EXHAUSTED and value.raise_error
            view=json.loads(task_execution(case.conn,realm_id=case.task.realm_id,task_id=case.task.task_id))
            metadata=view['invocations'][0]['provider']
            assert metadata['terminal']['http_status']==429 and metadata['terminal']['retry_after_us']==2_000_000
            assert metadata['terminal']['error_code']==ErrorCode.RESOURCE_EXHAUSTED
            assert metadata['settlement']['usage']['cost_microunits'] is None
            assert metadata['settlement']['liability_microunits']==60
            assert len(case.server.seen)==1
            with pytest.raises(StableError):
                await invoke(case,worker)
            assert len(case.server.seen)==1
            rows=case.conn.execute("SELECT payload_json FROM facts WHERE entity_id=? AND event_type='provider_terminal_observed'",(case.invocation,)).fetchall()
            assert len(rows)==1 and json.loads(rows[0][0])==metadata['terminal']
            assert 'Authorization' not in json.dumps(metadata) and 'synthetic-provider-secret' not in json.dumps(metadata)
            reopened=connect_store(case.root/'meta.db')
            try:
                assert json.loads(task_execution(reopened,realm_id=case.task.realm_id,task_id=case.task.task_id))['invocations'][0]['provider']==metadata
            finally:
                reopened.close()
        finally:
            await worker.close()
    asyncio.run(run())


@pytest.mark.parametrize('mode',['projection','fact','extra_field','missing_fact'])
def test_observation_tampering_is_refused_by_store_or_public_query(provider_host,mode):
    case=provider_host; case.server.mode='rate'
    async def run():
        worker=ProviderWorkerController(case.boot)
        try:
            await invoke(case,worker)
        finally:
            await worker.close()
    asyncio.run(run())
    if mode in ('fact','missing_fact'):
        with pytest.raises(sqlite3.IntegrityError,match='FACT_APPEND_ONLY'):
            if mode=='fact':
                case.conn.execute("UPDATE facts SET payload_json=? WHERE entity_id=? AND event_type='provider_terminal_observed'",(b'{}',case.invocation))
            else:
                case.conn.execute("DELETE FROM facts WHERE entity_id=? AND event_type='provider_terminal_observed'",(case.invocation,))
        case.conn.rollback()
        assert json.loads(task_execution(case.conn,realm_id=case.task.realm_id,task_id=case.task.task_id))['invocations'][0]['provider']['terminal']['retry_after_us']==2_000_000
        return
    else:
        raw=case.conn.execute('SELECT backend_ref_json FROM invocations WHERE invocation_id=?',(case.invocation,)).fetchone()[0]
        journal=json.loads(raw)
        journal['provider_terminal']['retry_after_us']=1
        if mode=='extra_field':
            journal['provider_terminal']['Authorization']='synthetic-forbidden-diagnostic'
        case.conn.execute('UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?',(canonical_json(journal),case.invocation))
    case.conn.commit()
    with pytest.raises(StableError) as caught:
        task_execution(case.conn,realm_id=case.task.realm_id,task_id=case.task.task_id)
    assert caught.value.code==ErrorCode.INTEGRITY_ERROR


def test_observation_and_settlement_rollback_together_and_conflicting_replay_is_refused(provider_host):
    case=provider_host
    observation=ProviderTerminalObservation('RESPONSE',ErrorCode.RESOURCE_EXHAUSTED,429,2_000_000)
    original=case.store.run_command
    def abort(mutator):
        def mutate(txn):
            mutator(txn)
            raise StableError(code=ErrorCode.INTERNAL,message='synthetic observation commit abort')
        return original(mutate)
    case.store.run_command=abort
    with pytest.raises(StableError):
        case.store.finish_invocation(case.invocation,error=ErrorCode.RESOURCE_EXHAUSTED,provider_outcome='CONFIRMED',provider_observation=observation)
    assert state(case)['settlement'] is None
    assert case.conn.execute("SELECT COUNT(*) FROM facts WHERE entity_id=? AND event_type IN ('provider_cost_settled','provider_terminal_observed')",(case.invocation,)).fetchone()[0]==0
    case.store.run_command=original
    kwargs=dict(error=ErrorCode.RESOURCE_EXHAUSTED,provider_outcome='CONFIRMED',provider_observation=observation)
    case.store.finish_invocation(case.invocation,**kwargs)
    before=case.conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_terminal_observed'").fetchone()[0]
    case.store.finish_invocation(case.invocation,**kwargs)
    assert case.conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_terminal_observed'").fetchone()[0]==before==1
    with pytest.raises(StableError) as caught:
        case.store.finish_invocation(case.invocation,**{**kwargs,'provider_observation':replace(observation,retry_after_us=1)})
    assert caught.value.code==ErrorCode.IDEMPOTENCY_CONFLICT


@pytest.mark.parametrize('kwargs',[{'state':[]},{'state':'UNKNOWN','error_code':None},
    {'state':'NOT_SENT','error_code':None},{'error_code':{}},{'error_code':'synthetic-secret-not-a-code'},
    {'http_status':True},{'http_status':600},{'retry_after_us':True,'http_status':429,'error_code':ErrorCode.RESOURCE_EXHAUSTED},
    {'retry_after_us':1,'http_status':200},{'retry_after_us':3_600_000_001,'http_status':429,'error_code':ErrorCode.RESOURCE_EXHAUSTED}])
def test_unbounded_or_untyped_transport_metadata_has_only_a_sanitized_failure(kwargs):
    with pytest.raises(StableError) as caught:
        ProviderTerminalObservation(**{'state':'RESPONSE',**kwargs})
    assert caught.value.code==ErrorCode.INVALID_RESULT and 'synthetic-secret' not in str(caught.value)
