"""Actual ordinary tool causal children, terminal/replay and token bindings."""
import asyncio
from dataclasses import replace
import json
import os

import pytest

from agent_meta_runtime.adapters import memory_host
from agent_meta_runtime.application.task_host import TaskSession
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.sdk import StableError
from agent_meta_runtime.sdk.packages import canonical_json
from test_resource_host import submit
from test_tool_result_policy import environment, CANARY


@pytest.mark.parametrize('backend', ['trusted_in_process','in_memory'])
@pytest.mark.parametrize('behavior', ['normal','schema','error'])
def test_ordinary_tool_child_has_exact_causal_authority_input_and_output_edges(tmp_path, backend, behavior):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, behavior, backend)
        try:
            task_id, terminal, execution = await submit(client, authority, {'api_key':CANARY})
            assert terminal['status'] == ('FAILED' if behavior == 'schema' else 'SUCCEEDED'), terminal
            tool = next(row for row in execution['invocations'] if row['kind'] == 'CAPABILITY')
            trace = await client.get_task_trace(task_id)
            child = next(row for row in trace['actions'] if row['action_id'] == tool['action_id'])
            assert child['action_id'] != execution['root_action_id'] and child['intent'] == 'capability_tool'
            assert child['causal_parent_action_id'] == execution['root_action_id']
            assert child['status'] == ('SUCCEEDED' if behavior == 'normal' else 'FAILED')
            assert child['consumed_budget']['steps'] == 1 and child['consumed_budget']['effects'] == 0
            edges = trace['edges']
            assert any(e['edge_type']=='caused_by' and e['from_id']==child['action_id'] and e['to_id']==execution['root_action_id'] for e in edges)
            assert any(e['edge_type']=='part_of' and e['from_id']==tool['invocation_id'] and e['to_id']==child['action_id'] for e in edges)
            assert any(e['edge_type']=='used' and e['from_id']==child['action_id'] and e['to_id']==tool['input_artifact_id'] for e in edges)
            admitted = {row[0] for row in daemon._conn.execute("SELECT grant_id FROM authority_uses WHERE action_id=? AND use_kind='host_invocation'", (tool['invocation_id'],))}
            linked = {e['to_id'] for e in edges if e['edge_type']=='authorized_by' and e['from_id']==child['action_id']}
            assert linked == admitted and len(linked) == 2
            if behavior == 'normal':
                assert any(e['edge_type']=='produced' and e['from_id']==tool['invocation_id'] and e['to_id']==tool['output_artifact_id'] for e in edges)
            assert len(trace['actions']) == 2
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('backend', ['trusted_in_process','in_memory'])
def test_confirmed_tool_replay_reuses_child_without_another_callback_or_use(tmp_path, monkeypatch, backend):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    original = TaskSession.invoke_tool
    async def replay(session, call):
        first = await original(session, call)
        session._ordinal -= 1
        session._pending.insert(0, call)
        assert await original(session, call) == first
        return first
    monkeypatch.setattr(TaskSession, 'invoke_tool', replay)
    async def run():
        daemon, client, authority = await environment(tmp_path, 'normal', backend)
        try:
            task_id, terminal, execution = await submit(client, authority, {'api_key':CANARY})
            assert terminal['status'] == 'SUCCEEDED', terminal
            assert execution['consumed_budget']['steps'] == 3 and len(execution['invocations']) == 3
            trace = await client.get_task_trace(task_id)
            assert len(trace['actions']) == 2
            child = next(row for row in trace['actions'] if row['intent'] == 'capability_tool')
            assert len([e for e in trace['events'] if e['entity_id']==child['action_id'] and e['event_type']=='action_started']) == 1
            assert len([e for e in trace['events'] if e['entity_id']==child['action_id'] and e['event_type']=='action_finished']) == 1
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('backend', ['trusted_in_process','in_memory'])
def test_tool_budget_refusal_creates_no_child(tmp_path, backend):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'normal', backend)
        try:
            task_id, terminal, execution = await submit(client, authority, {'api_key':CANARY}, budget={'max_steps':1})
            assert terminal['error'] == 'RESOURCE_EXHAUSTED'
            assert len(execution['invocations']) == 1 and execution['consumed_budget']['steps'] == 1
            assert len((await client.get_task_trace(task_id))['actions']) == 1
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_actual_execution_tokens_bind_models_to_root_and_tool_to_child(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    seen, tasks = [], []
    authorize = memory_host.MemoryHostActivities._authorize
    def observed(activities, request):
        pending = activities._pending[request.request_id]
        task = pending['task']
        payload = json.loads(request.authority_token)['payload']
        seen.append((payload['action_id'], pending['binding'].action_id))
        tasks.append((task,request.request_id,pending['capability_id'],pending['operation_id']))
        return authorize(activities,request)
    monkeypatch.setattr(memory_host.MemoryHostActivities, '_authorize', observed)
    async def run():
        daemon, client, authority = await environment(tmp_path, 'normal', 'in_memory')
        try:
            _, terminal, execution = await submit(client, authority, {'api_key':CANARY})
            assert terminal['status'] == 'SUCCEEDED', terminal
            expected = [execution['root_action_id'], execution['invocations'][1]['action_id'], execution['root_action_id']]
            assert seen == [(action,action) for action in expected]
            task, invocation, capability, operation = tasks[1]
            store = daemon._task_host.store
            for field, value in (('realm_id','realm://other'),('actor_id','principal://agent/01900000-0000-7000-8000-000000000001'),
                    ('task_id','task://01900000-0000-7000-8000-000000000001'),
                    ('serving_composition_id','composition://01900000-0000-7000-8000-000000000001'),('root_action_id',execution['invocations'][1]['action_id'])):
                # Root-owned binding lookup must refuse a different envelope,
                # even before any token is issued for it.
                with pytest.raises(StableError) as denied:
                    store.activity_action(replace(task, **{field:value}), invocation, capability, operation)
                assert denied.value.code == 'AUTHORITY_DENIED'
            with pytest.raises(StableError):
                store.activity_action(task, invocation, 'capability://wrong-target', operation)
            with pytest.raises(StableError):
                store.activity_action(task, invocation, capability, 'wrong-operation')
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_root_signed_token_cannot_substitute_task_root_for_the_tool_child(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    issue = memory_host.issue_execution_token
    connections = []
    def wrong_action(payload, **options):
        if payload['effect_kind'] == 'none':
            parent = connections[0].execute('SELECT causal_parent_action_id FROM actions WHERE action_id=?', (payload['action_id'],)).fetchone()[0]
            assert parent and parent != payload['action_id']
            payload = {**payload,'action_id':parent}
        return issue(payload, **options)
    monkeypatch.setattr(memory_host, 'issue_execution_token', wrong_action)
    async def run():
        daemon, client, authority = await environment(tmp_path, 'normal', 'in_memory')
        connections.append(daemon._conn)
        try:
            task_id, terminal, execution = await submit(client, authority, {'api_key':CANARY})
            assert terminal['error'] == 'AUTHORITY_DENIED', terminal
            assert len(execution['invocations']) == 2
            tool = execution['invocations'][1]
            assert tool.get('execution_binding') is None and tool['output_artifact_id'] is None
            child = next(row for row in (await client.get_task_trace(task_id))['actions'] if row['action_id']==tool['action_id'])
            assert child['status'] == 'FAILED'
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('backend', ['trusted_in_process','in_memory'])
def test_cancel_terminates_the_admitted_child_without_orphan_action(tmp_path, backend):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'wait', backend)
        try:
            reference = (await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                content=canonical_json({}),kind='task_input',media_type='application/json'))['artifact_id']
            task = await client.submit_task(realm_id='realm://main',actor_id=authority.actor_id,input_artifact_id=reference)
            end = asyncio.get_running_loop().time()+5
            while asyncio.get_running_loop().time()<end:
                execution = await client.get_task_execution(task.task_id)
                if any(row['kind']=='CAPABILITY' and row['status']=='RUNNING' for row in execution['invocations']):
                    break
                await asyncio.sleep(.01)
            else:
                raise AssertionError('tool did not reach its pending callback')
            await client.cancel_task(realm_id='realm://main',actor_id=authority.actor_id,task_id=task.task_id)
            terminal, done = await client.wait_task(task.task_id,timeout_s=5)
            assert done and terminal['status']=='CANCELLED',terminal
            children = [row for row in (await client.get_task_trace(task.task_id))['actions'] if row['intent']=='capability_tool']
            assert len(children)==1 and children[0]['status']=='FAILED'
            assert children[0]['error']=='EXTERNAL_EFFECT_UNKNOWN'
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())
