"""Signed public-only package -> public facade -> actual owned Scratch kernel."""

import asyncio
from dataclasses import replace
import json
import os
import time

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex, encode_package, build_manifest
from agent_meta_runtime.sdk.context import build_context_artifacts
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority


CAP = "capability://fixture.scratch"
NAMES = ["fixture.scratch.create", "fixture.scratch.execute", "fixture.scratch.release"]
OBS_NAMES = ["fixture.scratch.bindings", "fixture.scratch.inspect"]
RULES = [(["process.spawn"], ["scratch.create", "scratch.execute"]),
         (["external.irreversible"], ["scratch.execute"]),
         (["external.irreversible"], ["scratch.release"])]


def scratch_bundle(behavior="normal", *, permissions=True):
    bundle, _, grants = live_bundle()
    names = NAMES+OBS_NAMES if behavior.startswith('observe') else NAMES+['fixture.scratch.export'] if behavior.startswith('export') else NAMES
    code = '''
import json
from agent_meta_runtime.sdk.host import (HarnessAdapter, HealthStatus, ModelResponse, TextPart,
    ToolCallPart, ProviderUsage, ResourceAdapter, InvocationResult, ScratchCreate, ScratchExecution, ScratchRelease, ScratchBindings, ScratchInspect, ScratchExportCandidate, terminal_result)
from agent_meta_runtime.sdk.context import build_projection_input
from agent_meta_runtime.sdk.packages import canonical_json
BEHAVIOR = BEHAVIOR_VALUE
NAMES = NAMES_VALUE
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
    args = json.loads(request.task.input_content)
    if request.ordinal == 0 and BEHAVIOR=='release_input':
        return ModelResponse((ToolCallPart('release',NAMES[2],canonical_json({'session_id':args['session_id']}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
    if BEHAVIOR=='release_input':
        return ModelResponse((TextPart('released'),),'STOP',ProviderUsage(None,None,0))
    if request.ordinal == 0:
        return ModelResponse((ToolCallPart('create',NAMES[0],'{}'),),'TOOL_CALL',ProviderUsage(None,None,0))
    tools = [json.loads(bytes.fromhex(entry['content_hex'])) for entry in json.loads(request.history_content)
        if entry['role']=='tool' and entry.get('content_hex')]
    session = next(value['session_id'] for value in tools if value['schema']=='scratch-session-receipt/v1')
    if request.ordinal == 1:
        value = {'session_id':session,'source_artifact_id':args['source_artifact_id']}
        return ModelResponse((ToolCallPart('execute',NAMES[1],canonical_json(value).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
    if BEHAVIOR.startswith('export'):
        if request.ordinal==2:
            value = {'session_id':session,'source_artifact_ids':[args['source_artifact_id']],**args['export']}
            return ModelResponse((ToolCallPart('export',NAMES[3],canonical_json(value).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        if request.ordinal==3:
            return ModelResponse((ToolCallPart('release',NAMES[2],canonical_json({'session_id':session}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        return ModelResponse((TextPart('exported'),),'STOP',ProviderUsage(None,None,0))
    if BEHAVIOR.startswith('observe'):
        if BEHAVIOR=='observe_rebind' and request.ordinal==2 or BEHAVIOR=='observe_expired' and request.ordinal==4:
            return ModelResponse((ToolCallPart('execute-again',NAMES[1],canonical_json({'session_id':session,'source_artifact_id':args['rebind_source_artifact_id']}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        if BEHAVIOR=='observe_expired' and request.ordinal==5:
            old = next(value for value in tools if value['schema']=='scratch-bindings-receipt/v1')
            handle = next(item['handle'] for item in old['bindings'] if item['name']=='value')
            return ModelResponse((ToolCallPart('inspect-expired',NAMES[4],canonical_json({'session_id':session,'handle':handle}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        ordinal = request.ordinal-1 if BEHAVIOR=='observe_rebind' and request.ordinal>=3 else request.ordinal
        if ordinal==2:
            return ModelResponse((ToolCallPart('bindings',NAMES[3],canonical_json({'session_id':session}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        if ordinal==3:
            bindings = next(value for value in tools if value['schema']=='scratch-bindings-receipt/v1')
            binding = next(item for item in bindings['bindings'] if item['name']=='value')
            target = {'handle':binding['handle']} if BEHAVIOR=='observe_handle' else {'name':args.get('inspect_name','value')}
            return ModelResponse((ToolCallPart('inspect',NAMES[4],canonical_json({'session_id':session,**target,**args.get('inspect_budget',{})}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        if request.ordinal==4 and BEHAVIOR=='observe_nested':
            inspected = next(value for value in tools if value['schema']=='scratch-inspection-receipt/v1')
            handle = next(child['handle'] for name,child in inspected['node']['children'] if name=='child')
            return ModelResponse((ToolCallPart('inspect-child',NAMES[4],canonical_json({'session_id':session,'handle':handle}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        check = 5 if BEHAVIOR=='observe_nested' else 4
        if ordinal==check:
            return ModelResponse((ToolCallPart('inspect-calls',NAMES[4],canonical_json({'session_id':session,'name':'calls'}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        if ordinal==check+1:
            return ModelResponse((ToolCallPart('release',NAMES[2],canonical_json({'session_id':session}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
        return ModelResponse((TextPart('observed'),),'STOP',ProviderUsage(None,None,0))
    if request.ordinal == 2 and BEHAVIOR != 'keep':
        return ModelResponse((ToolCallPart('release',NAMES[2],canonical_json({'session_id':session}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
    if request.ordinal == 3 and BEHAVIOR=='repeat_release':
        return ModelResponse((ToolCallPart('release-again',NAMES[2],canonical_json({'session_id':session}).decode()),),'TOOL_CALL',ProviderUsage(None,None,0))
    return ModelResponse((TextPart('scratch complete'),),'STOP',ProviderUsage(None,None,0))
async def probe(request):
    return HealthStatus('READY','SCRATCH_PUBLIC_FIXTURE')
def plan(request):
    args = json.loads(request.call.arguments_json)
    if request.call.name == NAMES[0]:
        return ScratchCreate()
    if request.call.name == NAMES[1]:
        return ScratchExecution(args['session_id'],args['source_artifact_id'],request.task.deadline_at_us)
    if request.call.name=='fixture.scratch.export':
        for key in ('source_artifact_ids','export_names','dependency_artifact_ids','support_artifact_ids'):
            if key in args:
                args[key]=tuple(args[key])
        return ScratchExportCandidate(**args)
    if len(NAMES)>3 and request.call.name == NAMES[3]:
        return ScratchBindings(args['session_id'])
    if len(NAMES)>4 and request.call.name == NAMES[4]:
        return ScratchInspect(args['session_id'],name=args.get('name'),handle=args.get('handle'),
            **{key:args[key] for key in ('max_depth','max_items','max_bytes','max_ms') if key in args})
    return ScratchRelease(args['session_id'])
def normalize(receipt):
    if BEHAVIOR=='export_invalid' and receipt.contract=='scratch.export/v1':
        return InvocationResult(content=canonical_json([]))
    if (BEHAVIOR=='invalid' and receipt.contract=='scratch.execute/v1') or (BEHAVIOR=='invalid_create' and receipt.contract=='scratch.create/v1'):
        return InvocationResult(content=canonical_json([]))
    return InvocationResult(content=receipt.content)
def create():
    return HarnessAdapter(run_task,model,{},probe,resource_tools={name:ResourceAdapter(plan,normalize) for name in NAMES})
'''.replace('BEHAVIOR_VALUE', repr(behavior)).replace('NAMES_VALUE', repr(names)).encode()
    profile, artifacts = build_context_artifacts(input_schema={"type":"object"}, selected_operation_ids=names, provider_id="fixture")
    bundle.blobs.update(artifacts)
    provenance = bundle.doc({"schema":"fixture-provenance/v1", "source_files":{"probe.py":sha256_hex(code)}})
    bundle.meta = replace(bundle.meta, build_provenance_artifact_id=provenance, runtime_constraints={"context_profile_artifact_id":profile})
    package = bundle.add(encode_package(build_manifest(bundle.meta, {"probe.py":code}), {"probe.py":code}))
    model = json.loads(bundle.blobs[bundle.manifest["capability_descriptor_artifact_ids"][0]])
    model["artifact_id"] = package
    schema = bundle.doc({"type":"object"})
    operations = [{"operation_id":"probe.scratch", "input_schema_artifact_id":schema,
        "output_schema_artifact_id":schema, "effects":["none"], "required_permissions":[], "idempotency":"PURE", "retry_semantics":"NEVER"}]
    extra_rules = [(['artifact.put'],['scratch.export','artifact.put'])] if behavior.startswith('export') else [(['none'],['scratch.inspect']),(['none'],['scratch.inspect'])]
    for name, (effects, required) in zip(names, RULES+extra_rules):
        operations.append({"operation_id":name, "input_schema_artifact_id":schema, "output_schema_artifact_id":schema,
            "effects":effects, "required_permissions":required, "idempotency":"PURE" if effects==['none'] else "KEYED", "retry_semantics":"NEVER",
            "resource_contract":name.replace("fixture.", "")+"/v1"})
    descriptor = {"capability_id":CAP,"descriptor_revision":1,"artifact_id":package,"placement":"in_process",
        "trust_class":"builtin_or_signed","provides":[],"requires":[],"operations":operations}
    composition = json.loads(bundle.blobs[bundle.manifest["composition_template_artifact_id"]])
    composition["slots"]["model"]["artifact_id"] = package
    composition["slots"]["scratch"] = {**composition["slots"]["model"], "capability_id":CAP,
        "health_probe":{"operation_id":"probe.scratch"}}
    grants.append({"permission":"capability.invoke","scope":{"realm_id":"realm://main","targets":[{"type":"CAPABILITY","id":CAP}]}})
    if permissions:
        for permission in ("scratch.create","scratch.execute","scratch.release",*(['scratch.inspect'] if behavior.startswith('observe') else [])):
            grants.append({"permission":permission,"scope":{"realm_id":"realm://main","targets":[{"type":"CAPABILITY","id":CAP}]}})
    grants.append({"permission":"capability.invoke","scope":{"realm_id":"realm://main","targets":[{"type":"ARTIFACT_KIND","id":"source"}]}})
    if behavior.startswith('export'):
        for permission in ('scratch.export','artifact.put'):
            grants.append({'permission':permission,'scope':{'realm_id':'realm://main','targets':[{'type':'CAPABILITY','id':CAP}]}})
        grants.append({'permission':'capability.invoke','scope':{'realm_id':'realm://main','targets':[{'type':'ARTIFACT_KIND','id':'export_input'}]}})
    bundle.manifest.update(public_api_range=">=1.15.0 <2.0.0", package_artifact_id=package,
        build_provenance_artifact_id=provenance, capability_descriptor_artifact_ids=sorted([bundle.doc(model),bundle.doc(descriptor)]),
        composition_template_artifact_id=bundle.doc(composition), grant_requests_artifact_id=bundle.doc({"schema":"harness-grant-requests/v1","requests":grants}))
    return bundle, bundle.sign(), grants


@pytest.mark.parametrize('behavior',['observe_name','observe_handle','observe_nested'])
def test_public_bindings_and_inspection_have_real_source_action_and_no_user_hooks(tmp_path, behavior):
    pytest.importorskip('ipykernel')
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    source = '''calls=[]
class Meta(type):
    def __getattribute__(self,name):
        calls.append('meta')
        raise RuntimeError('METADATA_HOOK')
    def __eq__(self,other):
        calls.append('eq')
        raise RuntimeError('EQ_HOOK')
class Value(metaclass=Meta):
    @property
    def trouble(self):
        calls.append('property')
        raise RuntimeError('PROPERTY_HOOK')
    def __repr__(self):
        calls.append('repr')
        raise RuntimeError('REPR_HOOK')
class Child: pass
value=Value()
value.password='INSPECTION_SECRET_VALUE'
value.child=Child()
'''
    async def run():
        daemon,client,authority=await environment(tmp_path,behavior)
        try:
            _,terminal,execution=await submit(client,authority,source)
            assert terminal['status']=='SUCCEEDED', (terminal,execution)
            calls=[item for item in execution['invocations'] if item['kind']=='CAPABILITY']
            execute=next(item for item in calls if item['target']==CAP+'#'+NAMES[1])
            binding_call=next(item for item in calls if item['target']==CAP+'#'+OBS_NAMES[0])
            binding_receipt=json.loads(await client.get_artifact_content(binding_call['output_artifact_id']))
            binding=next(item for item in binding_receipt['bindings'] if item['name']=='value')
            assert binding['created_cell']==binding['last_changed_cell']==1
            assert binding['created_by_action_id']==binding['last_cell_action_id']==execute['action_id']
            assert binding['safe_summary']['type_name']=='Value' and binding['handle'].startswith('obs:')
            inspect_calls=[item for item in calls if item['target']==CAP+'#'+OBS_NAMES[1]]
            receipts=[json.loads(await client.get_artifact_content(item['output_artifact_id'])) for item in inspect_calls]
            assert 'INSPECTION_SECRET_VALUE' not in str(receipts)
            first=receipts[0]
            password=next(node for name,node in first['node']['children'] if name=='password')
            assert password['kind']=='redacted' and password['value']=='[REDACTED]'
            assert first['observed_by_action_id']==inspect_calls[0]['action_id']
            assert receipts[-1]['node']['children']==[]
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='scratch_cell_reserved'").fetchone()==(1,)
            assert daemon._conn.execute("SELECT status FROM scratch_bindings WHERE binding_name='value'").fetchone()==('RELEASED',)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('behavior',['observe_rebind','observe_expired'])
def test_binding_generations_use_each_real_cell_source_and_expire_old_weak_values(tmp_path,behavior):
    pytest.importorskip('ipykernel')
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon,client,authority=await environment(tmp_path,behavior)
        try:
            second=await client.put_artifact(realm_id='realm://main',actor_id=authority.actor_id,
                kind='source',media_type='text/x-python',content=b'value=Value()\nvalue.number=2\nimport gc\ngc.collect()')
            source='calls=[]\nclass Value: pass\nvalue=Value()\nvalue.number=1'
            _,terminal,execution=await submit(client,authority,source,extra={'rebind_source_artifact_id':second['artifact_id']})
            cells=[item for item in execution['invocations'] if item['target']==CAP+'#'+NAMES[1]]
            assert len(cells)==2
            if behavior=='observe_expired':
                assert terminal['error']=='HANDLE_EXPIRED', (terminal,execution)
            else:
                assert terminal['status']=='SUCCEEDED', (terminal,execution)
                binding_call=next(item for item in execution['invocations'] if item['target']==CAP+'#'+OBS_NAMES[0])
                receipt=json.loads(await client.get_artifact_content(binding_call['output_artifact_id']))
                binding=next(item for item in receipt['bindings'] if item['name']=='value')
                assert binding['created_cell']==1 and binding['last_changed_cell']==2
                assert binding['created_by_action_id']==cells[0]['action_id']
                assert binding['last_cell_action_id']==cells[1]['action_id']
                assert binding['source_artifact_id']==second['artifact_id']
            assert daemon._conn.execute("SELECT COUNT(*) FROM scratch_bindings WHERE binding_name='value'").fetchone()==(2,)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_inspection_rechecks_reserved_grant_after_wait_before_reading_native_values(tmp_path,monkeypatch):
    pytest.importorskip('ipykernel')
    from agent_meta_runtime.adapters.scratch_resources import OwnedScratchResources
    original=OwnedScratchResources._observe
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon,client,authority=await environment(tmp_path,'observe_name')
        control=await connect(tmp_path,authority=authority)
        async def revoked(host,task,invocation,request):
            rows=daemon._conn.execute('SELECT grant_id,permissions_json FROM authority_grants WHERE subject_id=? AND status=\'ACTIVE\'',(daemon._service_id,)).fetchall()
            grant=next(key for key,raw in rows if 'scratch.inspect' in json.loads(raw))
            await control.revoke_authority(realm_id='realm://main',actor_id=authority.actor_id,grant_id=grant)
            return await original(host,task,invocation,request)
        monkeypatch.setattr(OwnedScratchResources,'_observe',revoked)
        try:
            _,terminal,_=await submit(client,authority,'calls=[]\nclass Value: pass\nvalue=Value()')
            assert terminal['error']=='AUTHORITY_DENIED', terminal
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='scratch_inspection_published'").fetchone()==(0,)
            assert next(iter(daemon._scratch._calls._owners.values()))[1].ordinal==1
        finally:
            await control.aclose()
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('options,expected',[({'inspect_budget':{'max_depth':0,'max_items':1,'max_bytes':1024}},'SUCCEEDED'),
    ({'inspect_name':'value.__dict__'},'INVALID_RESULT')])
def test_public_inspection_budget_and_non_identifier_fail_closed(tmp_path,options,expected):
    pytest.importorskip('ipykernel')
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon,client,authority=await environment(tmp_path,'observe_name')
        try:
            _,terminal,execution=await submit(client,authority,'calls=[]\nclass Value: pass\nvalue=Value()\nvalue.items=list(range(1000))',extra=options)
            if expected=='SUCCEEDED':
                assert terminal['status']==expected,terminal
                call=next(item for item in execution['invocations'] if item['target']==CAP+'#'+OBS_NAMES[1])
                receipt=json.loads(await client.get_artifact_content(call['output_artifact_id']))
                assert receipt['node']['truncated'] and receipt['node']['children']==[]
            else:
                assert terminal['error']==expected,terminal
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='scratch_cell_reserved'").fetchone()==(1,)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


async def environment(root, behavior="normal", *, permissions=True):
    bundle, manifest, grants = scratch_bundle(behavior, permissions=permissions)
    authority = _authority(root)
    daemon = RuntimeDaemon(root, allow_insecure_credentials=os.name!='nt',
        trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
    await daemon.start()
    client = await connect(root, authority=authority)
    try:
        installed = await upload_install(client, authority, bundle, manifest)
        await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id,
            harness_id=installed.resource["harness_id"], composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
        await wait_refs(client, status="READY", serving=1)
        return daemon, client, authority
    except BaseException:
        await client.aclose()
        await daemon.close()
        raise


async def submit(client, authority, source, *, extra=None):
    uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
        content=source.encode(), kind="source", media_type="text/x-python")
    task_input = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
        content=canonical_json({"source_artifact_id":uploaded["artifact_id"],**(extra or {})}), kind="task_input", media_type="application/json")
    task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id,
        input_artifact_id=task_input["artifact_id"], deadline_at_us=time.time_ns()//1000+30_000_000)
    terminal, done = await client.wait_task(task.task_id, timeout_s=25)
    assert done, terminal
    return task.task_id, terminal, await client.get_task_execution(task.task_id)


def test_signed_public_package_creates_executes_releases_actual_kernel(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path)
        try:
            task, terminal, execution = await submit(client, authority, "answer=6*7\nprint(answer)")
            assert terminal["status"] == "SUCCEEDED", (terminal, execution)
            tools = [item for item in execution["invocations"] if item["kind"]=="CAPABILITY"]
            assert len(tools)==3 and all(item["action_id"]!=execution["root_action_id"] for item in tools)
            result = tools[1]["output_artifact_id"]
            receipt = json.loads(await client.get_artifact_content(result))
            value = json.loads(await client.get_artifact_content(receipt["stdout_artifact_id"]))
            assert value["text"].strip()=="42" and receipt["execution_count"]==1
            assert "answer" in receipt["declared_binding_names"]
            assert daemon._conn.execute("SELECT status FROM scratch_sessions").fetchall()==[("RELEASED",)]
            assert not list((tmp_path/"workspaces").iterdir())
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize("source,truncated", [
    ("print('Bearer ROOT_SCRATCH_OUTPUT_SECRET')\nfrom IPython.display import display\ndisplay({'application/json':{'password':'DISPLAY_SECRET'}},raw=True)", False),
    ("print('x'*1200000)", True),
])
def test_public_channel_artifacts_are_policy_redacted_and_bounded(tmp_path, source, truncated):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path)
        try:
            _, terminal, execution = await submit(client, authority, source)
            assert terminal['status']=='SUCCEEDED', terminal
            tool = next(item for item in execution['invocations'] if item['target']==CAP+'#'+NAMES[1])
            receipt = json.loads(await client.get_artifact_content(tool['output_artifact_id']))
            raw = await client.get_artifact_content(receipt['stdout_artifact_id'])
            assert len(raw)<=1024*1024 and receipt['stdout_truncated'] is truncated
            value = json.loads(raw)
            assert 'ROOT_SCRATCH_OUTPUT_SECRET' not in value['text']
            if not truncated:
                assert '[REDACTED]' in value['text']
                display = json.loads(await client.get_artifact_content(receipt['display_artifact_ids'][0]))
                assert display['bundle']['data']['application/json']['password']=='[REDACTED]'
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_public_normalization_failure_retains_known_native_effect(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'invalid')
        try:
            _, terminal, execution = await submit(client, authority, 'value=42')
            assert terminal['error']=='INVALID_RESULT', terminal
            native = daemon._conn.execute("SELECT payload_json FROM facts WHERE event_type='scratch_cell_observed'").fetchall()
            assert len(native)==1 and json.loads(native[0][0])['status']=='SUCCEEDED'
            failed = next(item for item in execution['invocations'] if item['target']==CAP+'#'+NAMES[1])
            assert failed['status']=='FAILED'
            assert daemon._conn.execute("SELECT status FROM scratch_sessions").fetchone()==('ACTIVE',)
        finally:
            await client.aclose()
            await daemon.close()
        assert not list((tmp_path/'workspaces').iterdir())
    asyncio.run(run())


def test_certificate_alone_does_not_grant_scratch_creation(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        bundle, manifest, _ = scratch_bundle(permissions=False)
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name!='nt',
            trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            for content in list(bundle.blobs.values()):
                await client.put_artifact(realm_id='realm://main', actor_id=authority.actor_id,
                    content=content, kind='code', media_type='application/octet-stream')
            report = await client.validate_harness_package(manifest)
            assert not report['valid'] and any('AUTHORITY_EXPANDED' in issue for issue in report['issues'])
            assert daemon._conn.execute('SELECT COUNT(*) FROM scratch_sessions').fetchone()==(0,)
            assert not list((tmp_path/'workspaces').iterdir())
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_failed_creation_normalizer_reaps_new_native_owner_and_workspace(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'invalid_create')
        try:
            _, terminal, execution = await submit(client, authority, 'print(42)')
            assert terminal['error']=='INVALID_RESULT', terminal
            assert len([item for item in execution['invocations'] if item['kind']=='CAPABILITY'])==1
            assert daemon._conn.execute('SELECT status FROM scratch_sessions').fetchall()==[('RELEASED',)]
            assert not daemon._scratch._calls._owners
            assert not list((tmp_path/'workspaces').iterdir())
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_public_cancel_waits_for_confirmed_native_interrupt(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'keep')
        control = await connect(tmp_path, authority=authority)
        pending = asyncio.create_task(submit(client, authority,
            "from pathlib import Path\nPath('entered').write_text('ready')\nwhile True: pass"))
        try:
            async with asyncio.timeout(20):
                while not list((tmp_path/'workspaces').glob('*/entered')):
                    await asyncio.sleep(.02)
            # Root-owned phase injection: the signed package itself uses only
            # SDK imports/facade and never sees this workspace or database.
            row = daemon._conn.execute("SELECT task_id FROM tasks WHERE status='RUNNING'").fetchone()
            started = time.monotonic()
            await control.cancel_task(realm_id='realm://main', actor_id=authority.actor_id, task_id=row[0])
            _, terminal, _ = await asyncio.wait_for(pending, 10)
            assert time.monotonic()-started < 10
            assert terminal['status']=='CANCELLED', terminal
            native = daemon._conn.execute("SELECT payload_json FROM facts WHERE event_type='scratch_cell_observed'").fetchall()
            assert len(native)==1 and json.loads(native[0][0])['status']=='INTERRUPTED'
            owner = next(iter(daemon._scratch._calls._owners.values()))[1]
            assert owner.state=='ACTIVE' and owner.ordinal==1
        finally:
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            await control.aclose()
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_repeated_public_release_has_one_cleanup_effect(tmp_path):
    pytest.importorskip("ipykernel")
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'repeat_release')
        try:
            _, terminal, execution = await submit(client, authority, 'print(42)')
            assert terminal['status']=='SUCCEEDED', terminal
            assert len([item for item in execution['invocations'] if item['kind']=='CAPABILITY'])==4
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='workspace_cleanup_completed'").fetchone()==(1,)
            release = next(item for item in execution['invocations'] if item['target']==CAP+'#'+NAMES[2])
            assert daemon._conn.execute("SELECT action_id FROM facts WHERE event_type='workspace_cleanup_completed'").fetchone()==(release['action_id'],)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


def test_confirmed_scratch_replay_skips_both_callbacks_and_native_submission(tmp_path, monkeypatch):
    pytest.importorskip("ipykernel")
    from agent_meta_runtime.application.task_host import TaskSession
    original = TaskSession._resource_tool
    replayed = []
    async def replay(session, call, *args):
        result = await original(session, call, *args)
        if call.name == NAMES[1]:
            owner = next(iter(session._scratch._calls._owners.values()))[1]
            assert owner.ordinal==1
            session._ordinal -= 1
            assert await original(session, call, *args)==result
            assert owner.ordinal==1
            replayed.append(True)
        return result
    monkeypatch.setattr(TaskSession, '_resource_tool', replay)
    run_init(tmp_path, insecure_dev_credential_file=os.name!='nt')
    async def run():
        daemon, client, authority = await environment(tmp_path)
        try:
            _, terminal, _ = await submit(client, authority, 'print(42)')
            assert terminal['status']=='SUCCEEDED' and replayed==[True]
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='scratch_dispatch_authorized'").fetchone()==(1,)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())
