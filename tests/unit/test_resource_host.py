"""Runtime-owned daemon integration; private State setup is not a consumer proof."""
import asyncio
from dataclasses import replace
import json
import os

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.host import ArtifactPut, ArtifactRead, StateRead, StateWrite, ResourceReceipt, ResourceAdapter
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex, encode_package, build_manifest
from agent_meta_runtime.sdk.context import build_context_artifacts
from agent_meta_runtime.adapters.store import StateCreateRequest, create_state
from agent_meta_runtime.adapters.store import StateWriteRequest, write_state_revision
from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
from agent_meta_runtime.application.task_host import TaskSession
from agent_meta_runtime.adapters.store import host_resources
from agent_meta_runtime.adapters.store.authority import RevokeGrantRequest, revoke_grant
from agent_meta_runtime.domain.errors import StableError, ErrorCode
from agent_meta_runtime.sdk import CommandAuthority
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority

CAP = 'capability://fixture.resource'
CONTRACTS = {
    'artifact.read/v1': ('PURE', ['none'], []),
    'artifact.put/v1': ('KEYED', ['artifact.put'], ['artifact.put']),
    'state.read/v1': ('PURE', ['state.read'], ['state.read']),
    'state.write/v1': ('KEYED', ['state.write'], ['state.write']),
}


def resource_bundle(contract, behavior='normal', *, resource_grants=True):
    bundle, _, grants = live_bundle()
    name = 'fixture.' + contract.split('/')[0]
    code = '''
import json
from agent_meta_runtime.sdk.host import (HarnessAdapter, HealthStatus, ModelResponse, TextPart, ToolCallPart,
    ProviderUsage, terminal_result, ResourceAdapter, InvocationResult, ArtifactRead, ArtifactPut, StateRead, StateWrite)
from agent_meta_runtime.sdk.context import build_projection_input
from agent_meta_runtime.sdk.packages import canonical_json
NAME = NAME_VALUE
CONTRACT = CONTRACT_VALUE
BEHAVIOR = BEHAVIOR_VALUE
async def run_task(task, host):
    projection = await host.project_context(build_projection_input(task))
    while True:
        response = await host.invoke_model(projection)
        calls = [part for part in response.parts if isinstance(part, ToolCallPart)]
        if not calls:
            return terminal_result(response)
        for call in calls:
            await host.invoke_tool(call)
async def model(request):
    if request.ordinal == 0:
        return ModelResponse((ToolCallPart('resource-call', NAME, canonical_json(json.loads(request.task.input_content)).decode()),), 'TOOL_CALL', ProviderUsage(None,None,0))
    if request.ordinal == 1 and BEHAVIOR == 'write_then_read':
        return ModelResponse((ToolCallPart('resource-read', 'fixture.state.read', canonical_json({'state_id':json.loads(request.task.input_content)['state_id']}).decode()),), 'TOOL_CALL', ProviderUsage(None,None,0))
    return ModelResponse((TextPart('resource complete'),), 'STOP', ProviderUsage(None,None,0))
async def probe(request):
    return HealthStatus('READY', 'RESOURCE_FIXTURE')
def plan(request):
    args = json.loads(request.call.arguments_json)
    if request.call.name == 'fixture.state.read':
        return StateRead(args['state_id'])
    if CONTRACT == 'artifact.put/v1':
        if BEHAVIOR == 'text':
            return ArtifactPut('note','text/plain; charset=utf-8',args['value'].encode('utf-8'))
        return ArtifactPut('note','application/json',canonical_json(args['value']))
    if CONTRACT == 'artifact.read/v1':
        return ArtifactRead(args['artifact_id'])
    if CONTRACT == 'state.read/v1':
        return StateRead(args['state_id'])
    return StateWrite(args['state_id'], args['expected_state_revision_id'], args['content_artifact_id'])
def normalize(receipt):
    value = {'artifact_id':receipt.artifact_id,'value':receipt.content.decode('utf-8') if BEHAVIOR=='text' else json.loads(receipt.content)}
    if receipt.state_id is not None:
        value.update(state_id=receipt.state_id,state_revision_id=receipt.state_revision_id)
    if BEHAVIOR == 'invalid_output':
        value = []
    return InvocationResult(content=canonical_json(value))
def create():
    resources = {NAME:ResourceAdapter(plan,normalize)}
    if BEHAVIOR == 'write_then_read':
        resources['fixture.state.read'] = ResourceAdapter(plan,normalize)
    return HarnessAdapter(run_task,model,{},probe,resource_tools=resources)
'''.replace('NAME_VALUE', repr(name)).replace('CONTRACT_VALUE', repr(contract)).replace('BEHAVIOR_VALUE', repr(behavior)).encode()
    profile, artifacts = build_context_artifacts(input_schema={'type': 'object'}, selected_operation_ids=[name, 'fixture.state.read'] if behavior=='write_then_read' else [name], provider_id='fixture')
    bundle.blobs.update(artifacts)
    provenance = bundle.doc({'schema': 'fixture-provenance/v1', 'source_files': {'probe.py': sha256_hex(code)}})
    bundle.meta = replace(bundle.meta, build_provenance_artifact_id=provenance, runtime_constraints={'context_profile_artifact_id': profile})
    package = bundle.add(encode_package(build_manifest(bundle.meta, {'probe.py': code}), {'probe.py': code}))
    model = json.loads(bundle.blobs[bundle.manifest['capability_descriptor_artifact_ids'][0]])
    model['artifact_id'] = package
    schema = bundle.doc({'type': 'object'})
    idem, effects, permissions = CONTRACTS[contract]
    tool = {'capability_id': CAP, 'descriptor_revision': 1, 'artifact_id': package, 'placement': 'in_process',
        'trust_class': 'builtin_or_signed', 'provides': [], 'requires': [], 'operations': [
            {'operation_id': 'probe.resource', 'input_schema_artifact_id': schema, 'output_schema_artifact_id': schema,
                'effects': ['none'], 'required_permissions': [], 'idempotency': 'PURE', 'retry_semantics': 'NEVER'},
            {'operation_id': name, 'input_schema_artifact_id': schema, 'output_schema_artifact_id': schema,
                'effects': effects, 'required_permissions': permissions, 'idempotency': idem,
                'retry_semantics': 'NEVER', 'resource_contract': contract}]}
    composition = json.loads(bundle.blobs[bundle.manifest['composition_template_artifact_id']])
    if behavior == 'write_then_read':
        tool['operations'].append({**tool['operations'][-1], 'operation_id':'fixture.state.read',
            'effects':['state.read'], 'required_permissions':['state.read'], 'idempotency':'PURE', 'resource_contract':'state.read/v1'})
    composition['slots']['model']['artifact_id'] = package
    composition['slots']['resource'] = {**composition['slots']['model'], 'capability_id': CAP,
        'health_probe': {'operation_id': 'probe.resource'}}
    def grant(permission, kind, identifier):
        return {'permission': permission, 'scope': {'realm_id': 'realm://main', 'targets': [{'type': kind, 'id': identifier}]}}
    grants.append(grant('capability.invoke', 'CAPABILITY', CAP))
    if contract.startswith('state.'):
        grants.append(grant(permissions[0], 'CAPABILITY', CAP if resource_grants else 'capability://wrong-owner'))
        if contract == 'state.write/v1':
            grants.append(grant('capability.invoke', 'ARTIFACT_KIND', 'note'))
        if behavior == 'write_then_read':
            grants.append(grant('state.read', 'CAPABILITY', CAP))
    else:
        grants.append(grant('artifact.put' if contract == 'artifact.put/v1' else 'capability.invoke', 'ARTIFACT_KIND', 'note' if resource_grants else 'wrong_note'))
    bundle.manifest.update(package_artifact_id=package, build_provenance_artifact_id=provenance,
        capability_descriptor_artifact_ids=sorted([bundle.doc(model), bundle.doc(tool)]),
        composition_template_artifact_id=bundle.doc(composition), grant_requests_artifact_id=bundle.doc({'schema': 'harness-grant-requests/v1', 'requests': grants}))
    return bundle, bundle.sign(), grants


def test_text_publication_sets_immutable_media_type_on_insert(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'artifact.put/v1', 'text')
        try:
            _, terminal, execution = await submit(client, authority, {'value':'Bearer TEXT_ARTIFACT_SECRET'})
            assert terminal['status']=='SUCCEEDED', terminal
            tool = next(item for item in execution['invocations'] if item['kind']=='CAPABILITY')
            result = json.loads(await client.get_artifact_content(tool['output_artifact_id']))
            assert result['value']=='[REDACTED]'
            assert await client.get_artifact_content(result['artifact_id'])==b'[REDACTED]'
            assert daemon._conn.execute('SELECT media_type FROM artifacts WHERE artifact_id=?', (result['artifact_id'],)).fetchone()==('text/plain; charset=utf-8',)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


async def environment(root, contract, behavior='normal', *, resource_grants=True):
    bundle, manifest, grants = resource_bundle(contract, behavior, resource_grants=resource_grants)
    authority = _authority(root)
    daemon = RuntimeDaemon(root, allow_insecure_credentials=os.name != 'nt', trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
    await daemon.start()
    client = await connect(root, authority=authority)
    installation = await upload_install(client, authority, bundle, manifest)
    await client.activate_harness(realm_id='realm://main', actor_id=authority.actor_id, harness_id=installation.resource['harness_id'],
        composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'], grant_requests=grants)
    await wait_refs(client, status='READY', serving=1)
    return daemon, client, authority


async def submit(client, authority, arguments, *, budget=None):
    artifact = await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
        content=canonical_json(arguments), kind='task_input', media_type='application/json')
    task = await client.submit_task(realm_id='realm://main', actor_id=authority.actor_id, input_artifact_id=artifact['artifact_id'],
        **({'budget':budget} if budget is not None else {}))
    terminal, done = await client.wait_task(task.task_id, timeout_s=10)
    assert done, terminal
    return task.task_id, terminal, await client.get_task_execution(task.task_id)


@pytest.mark.parametrize('contract', ['artifact.put/v1', 'artifact.read/v1', 'state.read/v1', 'state.write/v1'])
def test_resource_tool_commits_real_content_and_child_action(tmp_path, contract):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, contract)
        try:
            value = {'answer': 42}
            if contract == 'artifact.put/v1':
                arguments = {'value': value}
            else:
                artifact = await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                    content=canonical_json(value), kind='note', media_type='application/json')
                if contract == 'artifact.read/v1':
                    arguments = {'artifact_id': artifact['artifact_id']}
                else:
                    schema = await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                        content=canonical_json({'type':'object'}), kind='schema', media_type='application/json')
                    created = daemon._task_host.store.run_command(create_state(StateCreateRequest(CAP, schema['artifact_id'], artifact['artifact_id'])))
                    arguments = {'state_id': created['state_id']}
                    if contract == 'state.write/v1':
                        arguments.update(expected_state_revision_id=created['state_revision_id'], content_artifact_id=artifact['artifact_id'])
            task_id, terminal, execution = await submit(client, authority, arguments)
            assert terminal['status'] == 'SUCCEEDED', (terminal, execution)
            tool = next(row for row in execution['invocations'] if row['kind'] == 'CAPABILITY')
            result = json.loads(await client.get_artifact_content(tool['output_artifact_id']))
            assert result['value'] == value
            assert tool['action_id'] != execution['root_action_id']
            assert daemon._conn.execute('SELECT status FROM actions WHERE action_id=?', (tool['action_id'],)).fetchone() == ('SUCCEEDED',)
            assert execution['consumed_budget']['steps'] == 3
            assert execution['consumed_budget']['effects'] == (3 if contract in ('artifact.put/v1','state.write/v1') else 2)
            trace = await client.get_task_trace(task_id)
            assert any(edge['edge_type']=='caused_by' and edge['from_id']==tool['action_id'] and edge['to_id']==execution['root_action_id'] for edge in trace['edges'])
            assert any(edge['edge_type']=='authorized_by' and edge['from_id']==tool['action_id'] for edge in trace['edges'])
            if contract == 'state.write/v1':
                assert daemon._conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone() == (result['state_revision_id'], 2)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


@pytest.mark.parametrize('behavior', ['invalid_output', 'wrong_scope'])
def test_artifact_failure_publishes_no_resource(tmp_path, behavior):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'artifact.put/v1',
            'invalid_output' if behavior == 'invalid_output' else 'normal', resource_grants=behavior!='wrong_scope')
        try:
            _, terminal, execution = await submit(client, authority, {'value': {'unpublished': 42}})
            assert terminal['error'] == ('INVALID_RESULT' if behavior=='invalid_output' else 'AUTHORITY_DENIED'), terminal
            assert daemon._conn.execute("SELECT COUNT(*) FROM artifacts WHERE kind='note'").fetchone()[0] == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_committed'").fetchone()[0] == 0
            tools = [row for row in execution['invocations'] if row['kind']=='CAPABILITY']
            assert len(tools) == (1 if behavior=='invalid_output' else 0)
            assert execution['consumed_budget']['steps'] == (2 if behavior=='invalid_output' else 1)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


async def state_fixture(daemon, client, authority, *, purpose='GENERAL'):
    async def put(value, kind):
        return (await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
            content=canonical_json(value), kind=kind, media_type='application/json'))['artifact_id']
    old = await put({'value': 'before'}, 'note')
    new = await put({'value': 'after'}, 'note')
    schema = await put({'type':'object'}, 'schema')
    created = daemon._task_host.store.run_command(create_state(StateCreateRequest(CAP, schema, old, purpose=purpose)))
    return created, old, new, schema


@pytest.mark.parametrize('failure', ['invalid_output', 'cas_race', 'reserved', 'terminal_commit'])
def test_failed_state_resource_cannot_move_head(tmp_path, monkeypatch, failure):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.write/v1', 'invalid_output' if failure=='invalid_output' else 'normal')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority,
                purpose='SESSION_TRANSCRIPT' if failure=='reserved' else 'GENERAL')
            winner = None
            if failure=='cas_race':
                original = HostExecutionStore.prepare_resource
                def prepare(store, task, invocation, request):
                    nonlocal winner
                    value = original(store, task, invocation, request)
                    winner = store.run_command(write_state_revision(StateWriteRequest(created['state_id'], created['state_revision_id'],
                        1, schema, old, authority.actor_id)))
                    return value
                monkeypatch.setattr(HostExecutionStore, 'prepare_resource', prepare)
            if failure=='terminal_commit':
                def refused(request):
                    raise StableError(code=ErrorCode.INTERNAL, message='injected terminal write failure')
                monkeypatch.setattr(host_resources, 'finish_invocation', refused)
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id'],
                'expected_state_revision_id':created['state_revision_id'],'content_artifact_id':new})
            assert terminal['error'] == {'invalid_output':'INVALID_RESULT','cas_race':'REVISION_CONFLICT','reserved':'AUTHORITY_DENIED','terminal_commit':'INTERNAL'}[failure], terminal
            row = daemon._conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone()
            assert row == (winner['state_revision_id'], 2) if winner else row == (created['state_revision_id'], 1)
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_committed'").fetchone()[0] == 0
            assert daemon._conn.execute('SELECT COUNT(*) FROM state_revisions WHERE state_id=?', (created['state_id'],)).fetchone()[0] == (2 if winner else 1)
            tools = [row for row in execution['invocations'] if row['kind']=='CAPABILITY']
            assert len(tools) == (0 if failure=='reserved' else 1)
            if tools:
                assert daemon._conn.execute('SELECT status FROM actions WHERE action_id=?', (tools[0]['action_id'],)).fetchone() == ('FAILED',)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_state_read_sees_own_committed_overlay(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.write/v1', 'write_then_read')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority)
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id'],
                'expected_state_revision_id':created['state_revision_id'],'content_artifact_id':new})
            assert terminal['status']=='SUCCEEDED', (terminal, execution)
            tools = [row for row in execution['invocations'] if row['kind']=='CAPABILITY']
            assert len(tools)==2
            results = [json.loads(await client.get_artifact_content(row['output_artifact_id'])) for row in tools]
            assert all(result['value']=={'value':'after'} for result in results)
            assert results[0]['state_revision_id']==results[1]['state_revision_id']!=created['state_revision_id']
            assert execution['consumed_budget']['steps']==5 and execution['consumed_budget']['effects']==4
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_confirmed_resource_replay_skips_both_callbacks_and_second_write(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    original = TaskSession._resource_tool
    callbacks = TaskSession._resource_callback
    calls = []
    def callback(function, value):
        calls.append(function)
        return callbacks(function, value)
    async def replayed(session, *args):
        result = await original(session, *args)
        count = len(calls)
        session._ordinal -= 1
        assert await original(session, *args)==result
        assert len(calls)==count==2
        return result
    monkeypatch.setattr(TaskSession, '_resource_callback', staticmethod(callback))
    monkeypatch.setattr(TaskSession, '_resource_tool', replayed)
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.write/v1')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority)
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id'],
                'expected_state_revision_id':created['state_revision_id'],'content_artifact_id':new})
            assert terminal['status']=='SUCCEEDED', terminal
            assert len(execution['invocations'])==3 and execution['consumed_budget']['steps']==3
            assert daemon._conn.execute('SELECT cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone() == (2,)
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_committed'").fetchone()[0] == 1
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_resource_actor_cannot_borrow_installation_or_root_authority(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, root, authority = await environment(tmp_path, 'artifact.put/v1')
        client = None
        try:
            key = Ed25519PrivateKey.generate()
            actor = (await root.create_principal(realm_id='realm://main', actor_id=authority.actor_id,
                kind='AGENT', public_key=key.public_key().public_bytes_raw())).resource['principal_id']
            grant = (await root.delegate_authority(realm_id='realm://main', actor_id=authority.actor_id, subject_id=actor,
                permissions=['task.submit','model.invoke','capability.invoke'], scope={'realm_id':'realm://main','targets':[{'type':'REALM_ALL'}]})).resource['grant_id']
            own = CommandAuthority(actor, grant, key.sign)
            client = await connect(tmp_path, authority=own)
            input = await root.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                content=canonical_json({'value':{'unauthorized':True}}), kind='task_input', media_type='application/json')
            task = await client.submit_task(realm_id='realm://main', actor_id=actor, input_artifact_id=input['artifact_id'])
            terminal, done = await root.wait_task(task.task_id, timeout_s=10)
            assert done and terminal['error']=='AUTHORITY_DENIED', terminal
            execution = await root.get_task_execution(task.task_id)
            assert [row['kind'] for row in execution['invocations']]==['MODEL']
            assert daemon._conn.execute("SELECT COUNT(*) FROM artifacts WHERE kind='note'").fetchone()[0]==0
        finally:
            if client:
                await client.aclose()
            await root.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_resource_budget_refusal_rolls_back_grant_use_and_child_action(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'artifact.put/v1')
        try:
            _, terminal, execution = await submit(client, authority, {'value':{'budget':True}}, budget={'max_steps':1})
            assert terminal['error']=='RESOURCE_EXHAUSTED', terminal
            assert execution['consumed_budget']['steps']==1 and len(execution['invocations'])==1
            assert daemon._conn.execute("SELECT COUNT(*) FROM actions WHERE intent='capability_resource'").fetchone()[0]==0
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_reserved'").fetchone()[0]==0
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_state_write_requires_authority_over_source_artifact_kind(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.write/v1')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority)
            forbidden = (await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                content=canonical_json({'unavailable':True}), kind='other_note', media_type='application/json'))['artifact_id']
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id'],
                'expected_state_revision_id':created['state_revision_id'],'content_artifact_id':forbidden})
            assert terminal['error']=='AUTHORITY_DENIED', terminal
            assert len(execution['invocations'])==1
            assert daemon._conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone()==(created['state_revision_id'],1)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_resource_commit_rechecks_its_reserved_service_grant(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.write/v1')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority)
            original = HostExecutionStore.prepare_resource
            def revoked(store, task, invocation, request):
                value = original(store, task, invocation, request)
                reservation = host_resources.read_reservation(store, invocation)
                grant_id = next(grant for grant, claims in reservation['grants'].items()
                    if any(claim['permission']=='state.write' for claim in claims)
                    and store.conn.execute('SELECT subject_id FROM authority_grants WHERE grant_id=?', (grant,)).fetchone()[0]==store.service_id)
                store.run_command(revoke_grant(RevokeGrantRequest(grant_id)))
                return value
            monkeypatch.setattr(HostExecutionStore,'prepare_resource',revoked)
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id'],
                'expected_state_revision_id':created['state_revision_id'],'content_artifact_id':new})
            assert terminal['error']=='AUTHORITY_DENIED', terminal
            assert daemon._conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone()==(created['state_revision_id'],1)
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_committed'").fetchone()[0]==0
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_failed_resource_replay_preserves_fatal_validation_semantics(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    original = TaskSession._resource_tool
    async def replayed(session, *args):
        with pytest.raises(StableError) as first:
            await original(session, *args)
        session._ordinal -= 1
        with pytest.raises(StableError) as second:
            await original(session, *args)
        assert first.value.code==second.value.code=='INVALID_RESULT'
        raise first.value
    monkeypatch.setattr(TaskSession,'_resource_tool',replayed)
    async def scenario():
        daemon, client, authority = await environment(tmp_path,'artifact.put/v1','invalid_output')
        try:
            _, terminal, execution = await submit(client,authority,{'value':{'unpublished':'replay'}})
            assert terminal['error']=='INVALID_RESULT', terminal
            assert len(execution['invocations'])==2 and execution['consumed_budget']['steps']==2
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='resource_call_failed'").fetchone()[0]==1
            assert daemon._conn.execute("SELECT COUNT(*) FROM artifacts WHERE kind='note'").fetchone()[0]==0
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_resource_redacts_before_plan_journal_content_and_output_publication(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    canary = 'RESOURCE_SECRET_CANARY_9c1f7'
    async def scenario():
        daemon, client, authority = await environment(tmp_path,'artifact.put/v1')
        try:
            _, terminal, execution = await submit(client,authority,{'value':{'api_key':canary,'public':'allowed'}})
            assert terminal['status']=='SUCCEEDED', terminal
            tool = next(row for row in execution['invocations'] if row['kind']=='CAPABILITY')
            request = await client.get_artifact_content(tool['input_artifact_id'])
            result_raw = await client.get_artifact_content(tool['output_artifact_id'])
            result = json.loads(result_raw)
            content = await client.get_artifact_content(result['artifact_id'])
            assert json.loads(content)=={'api_key':'[REDACTED]','public':'allowed'}
            assert all(canary.encode() not in value for value in (request,result_raw,content))
            payloads = daemon._conn.execute("SELECT payload_json FROM facts WHERE event_type IN ('resource_call_reserved','resource_call_committed')").fetchall()
            assert payloads and all(canary.encode() not in row[0] for row in payloads)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_state_read_keeps_frozen_revision_after_global_write(tmp_path, monkeypatch):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def scenario():
        daemon, client, authority = await environment(tmp_path, 'state.read/v1')
        try:
            created, old, new, schema = await state_fixture(daemon, client, authority)
            original = HostExecutionStore.prepare_resource
            def prepare(store, task, invocation, request):
                store.run_command(write_state_revision(StateWriteRequest(created['state_id'], created['state_revision_id'],
                    1, schema, new, authority.actor_id)))
                return original(store, task, invocation, request)
            monkeypatch.setattr(HostExecutionStore, 'prepare_resource', prepare)
            _, terminal, execution = await submit(client, authority, {'state_id':created['state_id']})
            assert terminal['status']=='SUCCEEDED', terminal
            tool = next(row for row in execution['invocations'] if row['kind']=='CAPABILITY')
            result = json.loads(await client.get_artifact_content(tool['output_artifact_id']))
            assert result['value']=={'value':'before'} and result['state_revision_id']==created['state_revision_id']
            assert daemon._conn.execute('SELECT cas_revision FROM managed_states WHERE state_id=?', (created['state_id'],)).fetchone() == (2,)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())
