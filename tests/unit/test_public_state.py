"""Signed State management through real IPC; no direct State setup/writes."""
import asyncio
from contextlib import asynccontextmanager
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from agent_meta_runtime.sdk import CommandAuthority, StableError, connect
from agent_meta_runtime.sdk.packages import canonical_json
from agent_meta_runtime.adapters.store.gc import collect_marks
from test_resource_host import CAP, environment, submit
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.adapters.store import state_management
from agent_meta_runtime.domain.errors import ErrorCode
from agent_meta_runtime.interfaces.cli.main import main as cli_main
from test_resource_host import resource_bundle
from test_bound_harness import upload_install, wait_refs
from test_daemon_lifecycle import _authority
from agent_meta_runtime.sdk.packages import sha256_hex

REALM='realm://main'


@asynccontextmanager
async def running(root,contract='state.write/v1'):
    run_init(root,insecure_dev_credential_file=os.name!='nt')
    daemon,client,authority=await environment(root,contract)
    try:
        yield daemon,client,authority
    finally:
        await client.aclose()
        await daemon.close()


async def artifact(client,authority,value,kind='note'):
    return (await client.put_artifact(realm_id=REALM,actor_id=authority.actor_id,content=canonical_json(value),kind=kind,media_type='application/json'))['artifact_id']


async def initialized(client,authority,*,purpose='GENERAL',schema=None,value=None):
    schema_id=await artifact(client,authority,schema if schema is not None else {'type':'object'},'schema')
    content=await artifact(client,authority,value if value is not None else {'value':1})
    result=await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,
        schema_id=schema_id,content_artifact_id=content,purpose=purpose)
    return result.resource


async def actor(root,path,authority,permissions,*,targets=None,constraints=None):
    key=Ed25519PrivateKey.generate()
    identity=(await root.create_principal(realm_id=REALM,actor_id=authority.actor_id,kind='AGENT',public_key=key.public_key().public_bytes_raw())).resource['principal_id']
    delegated=(await root.delegate_authority(realm_id=REALM,actor_id=authority.actor_id,subject_id=identity,
        permissions=permissions,scope={'realm_id':REALM,'targets':targets or [{'type':'REALM_ALL'}]},constraints=constraints)).resource
    own=CommandAuthority(identity,delegated['grant_id'],key.sign)
    return await connect(path,authority=own),own


def test_public_state_create_read_write_and_historical_snapshot(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            assert initial['cas_revision']==1 and initial['state_revision_id']==initial['current_revision_id']
            assert initial['controller_principal_id']==authority.actor_id
            next_content=await artifact(client,authority,{'value':2})
            write=client.build_state_write(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],
                expected_state_revision_id=initial['state_revision_id'],expected_cas_revision=1,
                schema_id=initial['schema_id'],content_artifact_id=next_content)
            changed=await client.execute_command('agent_meta.public.v1.State.Write',write)
            assert changed.resource['cas_revision']==2 and changed.resource['content_artifact_id']==next_content
            old=await client.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],state_revision_id=initial['state_revision_id'])
            assert old['content_artifact_id']==initial['content_artifact_id']
            assert old['current_revision_id']==changed.resource['state_revision_id'] and old['cas_revision']==2
            assert await client.execute_command('agent_meta.public.v1.State.Write',write)==changed
            current=await client.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
            assert current['content_artifact_id']==next_content
    asyncio.run(scenario())


def test_audited_read_charges_once_and_replay_keeps_original_snapshot(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,root,authority):
            initial=await initialized(root,authority)
            reader,own=await actor(root,tmp_path,authority,['state.read'],constraints={'max_uses':1},
                targets=[{'type':'CAPABILITY','id':CAP}])
            try:
                command=reader.build_state_read(realm_id=REALM,actor_id=own.actor_id,state_id=initial['state_id'])
                first=await reader.execute_command('agent_meta.public.v1.State.Get',command)
                next_content=await artifact(root,authority,{'value':2})
                await root.write_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],
                    expected_state_revision_id=initial['state_revision_id'],expected_cas_revision=1,
                    schema_id=initial['schema_id'],content_artifact_id=next_content)
                assert await reader.execute_command('agent_meta.public.v1.State.Get',command)==first
                assert first.resource['cas_revision']==1
                with pytest.raises(StableError) as denied:
                    await reader.get_state(realm_id=REALM,actor_id=own.actor_id,state_id=initial['state_id'])
                assert denied.value.code=='AUTHORITY_DENIED'
                assert daemon._conn.execute('SELECT COUNT(*) FROM authority_uses WHERE grant_id=?',(own.authority_grant_id,)).fetchone()==(1,)
                await root.revoke_authority(realm_id=REALM,actor_id=authority.actor_id,grant_id=own.authority_grant_id)
                assert await reader.execute_command('agent_meta.public.v1.State.Get',command)==first
            finally:
                await reader.aclose()
    asyncio.run(scenario())


@pytest.mark.parametrize('wrong',['revision','cas','schema','invalid_content'])
def test_state_write_conflicts_never_move_head(tmp_path,wrong):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            content=await artifact(client,authority,[] if wrong=='invalid_content' else {'value':2})
            other_schema=await artifact(client,authority,{'type':'array'},'schema')
            values={'realm_id':REALM,'actor_id':authority.actor_id,'state_id':initial['state_id'],
                'expected_state_revision_id':initial['state_revision_id'],'expected_cas_revision':1,
                'schema_id':initial['schema_id'],'content_artifact_id':content}
            if wrong=='revision':
                values['expected_state_revision_id']='state-revision://01900000-0000-7000-8000-000000000001'
            if wrong=='cas': values['expected_cas_revision']=2
            if wrong=='schema': values['schema_id']=other_schema
            with pytest.raises(StableError) as failure:
                await client.write_state(**values)
            assert failure.value.code==('INVALID_ARGUMENT' if wrong=='invalid_content' else 'REVISION_CONFLICT')
            current=await client.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
            assert current['state_revision_id']==initial['state_revision_id'] and current['cas_revision']==1
    asyncio.run(scenario())


def test_creation_redacts_and_pins_schema_and_policy_through_gc(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority,value={'secret':'STATE_MANAGEMENT_CANARY','public':42})
            content=json.loads(await client.get_artifact_content(initial['content_artifact_id']))
            assert content=={'secret':'[REDACTED]','public':42}
            marks=collect_marks(daemon._conn)
            assert initial['schema_id'].rsplit('/',1)[1] in marks
            assert initial['redaction_policy_artifact_id'].rsplit('/',1)[1] in marks
    asyncio.run(scenario())


@pytest.mark.parametrize('contract',['state.read/v1','state.write/v1'])
def test_model_resources_cannot_access_protected_session_state(tmp_path,contract):
    async def scenario():
        async with running(tmp_path,contract) as (daemon,client,authority):
            initial=await initialized(client,authority,purpose='SESSION_JOURNAL')
            values={'state_id':initial['state_id']}
            if contract=='state.write/v1':
                values.update(expected_state_revision_id=initial['state_revision_id'],content_artifact_id=initial['content_artifact_id'])
            _,terminal,execution=await submit(client,authority,values)
            assert terminal['error']=='AUTHORITY_DENIED',terminal
            assert [row['kind'] for row in execution['invocations']]==['MODEL']
    asyncio.run(scenario())


def test_protected_state_controller_is_derived_from_signature(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,root,authority):
            first,a=await actor(root,tmp_path,authority,['state.read','state.write','capability.invoke'])
            second,b=await actor(root,tmp_path,authority,['state.read','state.write','capability.invoke'])
            try:
                schema=await artifact(root,authority,{'type':'object'},'schema')
                content=await artifact(root,authority,{'value':1})
                initial=(await first.create_state(realm_id=REALM,actor_id=a.actor_id,owner_id=CAP,
                    schema_id=schema,content_artifact_id=content,purpose='SESSION_TRANSCRIPT')).resource
                assert initial['controller_principal_id']==a.actor_id
                with pytest.raises(StableError) as denied:
                    await second.get_state(realm_id=REALM,actor_id=b.actor_id,state_id=initial['state_id'])
                assert denied.value.code=='AUTHORITY_DENIED'
                view=await first.get_state(realm_id=REALM,actor_id=a.actor_id,state_id=initial['state_id'])
                assert view['state_revision_id']==initial['state_revision_id']
                admin=await root.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
                assert admin['controller_principal_id']==a.actor_id
            finally:
                await first.aclose(); await second.aclose()
    asyncio.run(scenario())


def test_committed_write_recovers_original_receipt_across_daemon_restart(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            content=await artifact(client,authority,{'value':'after restart'})
            command=client.build_state_write(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],
                expected_state_revision_id=initial['state_revision_id'],expected_cas_revision=1,
                schema_id=initial['schema_id'],content_artifact_id=content)
            expected=await client.execute_command('agent_meta.public.v1.State.Write',command)
            trusted=daemon._trusted_publishers
            await client.aclose(); await daemon.close()
            restarted=RuntimeDaemon(tmp_path,allow_insecure_credentials=os.name!='nt',trusted_publishers=trusted)
            await restarted.start()
            recovered=await connect(tmp_path,authority=authority)
            try:
                assert await recovered.execute_command('agent_meta.public.v1.State.Write',command)==expected
                current=await recovered.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
                assert current['cas_revision']==2 and current['content_artifact_id']==content
                assert restarted._conn.execute('SELECT COUNT(*) FROM state_revisions WHERE state_id=?',(initial['state_id'],)).fetchone()==(2,)
            finally:
                await recovered.aclose(); await restarted.close()
    asyncio.run(scenario())


def test_write_failure_rolls_back_derived_content_revision_history_and_grant_use(tmp_path,monkeypatch):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            content=await artifact(client,authority,{'secret':'ROLLBACK_CANARY','value':2})
            command=client.build_state_write(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],
                expected_state_revision_id=initial['state_revision_id'],expected_cas_revision=1,
                schema_id=initial['schema_id'],content_artifact_id=content)
            before=daemon._conn.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0]
            original=state_management.write_state_revision
            def refused(request):
                mutate=original(request)
                def fail(txn):
                    mutate(txn)
                    raise StableError(code=ErrorCode.INTERNAL,message='injected failure after revision/history')
                return fail
            monkeypatch.setattr(state_management,'write_state_revision',refused)
            with pytest.raises(StableError) as failure:
                await client.execute_command('agent_meta.public.v1.State.Write',command)
            assert failure.value.code=='INTERNAL'
            assert daemon._conn.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0]==before
            assert daemon._conn.execute('SELECT COUNT(*) FROM state_revisions WHERE state_id=?',(initial['state_id'],)).fetchone()==(1,)
            assert daemon._conn.execute('SELECT COUNT(*) FROM state_ref_history WHERE state_id=?',(initial['state_id'],)).fetchone()==(1,)
            assert daemon._conn.execute('SELECT current_revision_id,cas_revision FROM managed_states WHERE state_id=?',(initial['state_id'],)).fetchone()==(initial['state_revision_id'],1)
    asyncio.run(scenario())


def test_nullable_state_schema_and_unknown_assertion_fail_closed(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            nullable=await artifact(client,authority,{'type':['string','null']},'schema')
            content=await artifact(client,authority,None)
            created=(await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,
                schema_id=nullable,content_artifact_id=content)).resource
            assert json.loads(await client.get_artifact_content(created['content_artifact_id'])) is None
            unsupported=await artifact(client,authority,{'type':'object','properties':{'unused':{'oneOf':[{'type':'string'}]}}},'schema')
            empty=await artifact(client,authority,{})
            with pytest.raises(StableError) as failure:
                await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,schema_id=unsupported,content_artifact_id=empty)
            assert failure.value.code=='FEATURE_UNAVAILABLE'
    asyncio.run(scenario())


def test_public_amount_ceiling_is_refused_before_a_state_read_grant_exists(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,root,authority):
            initial=await initialized(root,authority)
            before=daemon._conn.execute('SELECT COUNT(*) FROM authority_grants').fetchone()[0]
            with pytest.raises(StableError) as failure:
                await actor(root,tmp_path,authority,['state.read'],constraints={'resource_ceiling':{'memory_bytes':0}})
            assert failure.value.code=='FEATURE_UNAVAILABLE'
            assert daemon._conn.execute('SELECT COUNT(*) FROM authority_grants').fetchone()[0]==before
    asyncio.run(scenario())


def test_state_source_kind_requires_the_selected_grants_actual_scope(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,root,authority):
            schema=await artifact(root,authority,{'type':'object'},'schema')
            content=await artifact(root,authority,{'value':1})
            client,own=await actor(root,tmp_path,authority,['state.write','capability.invoke'],targets=[{'type':'CAPABILITY','id':CAP}])
            try:
                with pytest.raises(StableError) as denied:
                    await client.create_state(realm_id=REALM,actor_id=own.actor_id,owner_id=CAP,schema_id=schema,content_artifact_id=content)
                assert denied.value.code=='AUTHORITY_DENIED'
                assert daemon._conn.execute('SELECT COUNT(*) FROM managed_states').fetchone()==(0,)
                assert daemon._conn.execute('SELECT COUNT(*) FROM authority_uses WHERE grant_id=?',(own.authority_grant_id,)).fetchone()==(0,)
            finally:
                await client.aclose()
    asyncio.run(scenario())


def test_task_resource_write_honors_public_states_pinned_stricter_policy(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            template=await initialized(client,authority)
            policy=json.loads(await client.get_artifact_content(template['redaction_policy_artifact_id']))
            policy['redact_keys']=sorted(set(policy['redact_keys'])|{'special'})
            policy_ref=await artifact(client,authority,policy,'policy')
            initial_ref=await artifact(client,authority,{'special':'FIRST_PRIVATE_VALUE','normal':1})
            initial=(await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,
                schema_id=template['schema_id'],content_artifact_id=initial_ref,redaction_policy_artifact_id=policy_ref)).resource
            next_ref=await artifact(client,authority,{'special':'SECOND_PRIVATE_VALUE','normal':2})
            _,terminal,execution=await submit(client,authority,{'state_id':initial['state_id'],
                'expected_state_revision_id':initial['state_revision_id'],'content_artifact_id':next_ref})
            assert terminal['status']=='SUCCEEDED',terminal
            current=await client.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
            assert current['cas_revision']==2 and current['redaction_policy_artifact_id']==policy_ref
            assert json.loads(await client.get_artifact_content(current['content_artifact_id']))=={'special':'[REDACTED]','normal':2}
    asyncio.run(scenario())


def test_state_writeback_records_the_completed_tasks_causal_parent(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            content=await artifact(client,authority,{'value':2})
            _,terminal,execution=await submit(client,authority,{'state_id':initial['state_id'],
                'expected_state_revision_id':initial['state_revision_id'],'content_artifact_id':content})
            assert terminal['status']=='SUCCEEDED',terminal
            current=await client.get_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'])
            next_content=await artifact(client,authority,{'value':3})
            result=await client.write_state(realm_id=REALM,actor_id=authority.actor_id,state_id=initial['state_id'],
                expected_state_revision_id=current['state_revision_id'],expected_cas_revision=2,
                schema_id=current['schema_id'],content_artifact_id=next_content,causal_parent_action_id=execution['root_action_id'])
            # The published Why contract walks incoming references. Inspect
            # the completed Task Action to see its new State writeback.
            explanation=await client.why(execution['root_action_id'])
            assert any(edge[1]=='caused_by' and edge[0]==result.resource['state_revision_id']
                and edge[2]==execution['root_action_id'] for edge in explanation['edges'])
    asyncio.run(scenario())


def test_state_cli_dry_run_requires_no_live_daemon_and_leaves_store_unchanged(tmp_path,capsys):
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    before=(tmp_path/'meta.db').read_bytes()
    code=cli_main(['--data-dir',str(tmp_path),'--output','json',*(['--insecure-dev-credential-file'] if os.name!='nt' else []),
        '--dry-run','state','get','state://01900000-0000-7000-8000-000000000000'])
    assert code==0
    result=json.loads(capsys.readouterr().out)['result']
    assert result['dry_run'] and result['requires_server_validation']
    assert (tmp_path/'meta.db').read_bytes()==before


def test_redaction_expansion_is_bounded_before_state_publication(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            schema=await artifact(client,authority,{'type':'object'},'schema')
            value={'pad':'x'*(1024*1024-3000),'entries':[{'secret':''} for _ in range(150)]}
            assert len(canonical_json(value))<=1024*1024
            content=await artifact(client,authority,value)
            with pytest.raises(StableError) as failure:
                await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,schema_id=schema,content_artifact_id=content)
            assert failure.value.code=='RESOURCE_EXHAUSTED'
            assert daemon._conn.execute('SELECT COUNT(*) FROM managed_states').fetchone()==(0,)
    asyncio.run(scenario())


def test_state_policy_cannot_repeat_redaction_patterns(tmp_path):
    async def scenario():
        async with running(tmp_path) as (daemon,client,authority):
            initial=await initialized(client,authority)
            policy=json.loads(await client.get_artifact_content(initial['redaction_policy_artifact_id']))
            policy['patterns'].append(policy['patterns'][0])
            invalid=await artifact(client,authority,policy,'policy')
            with pytest.raises(StableError) as failure:
                await client.create_state(realm_id=REALM,actor_id=authority.actor_id,owner_id=CAP,
                    schema_id=initial['schema_id'],content_artifact_id=initial['content_artifact_id'],redaction_policy_artifact_id=invalid)
            assert failure.value.code=='FAILED_PRECONDITION'
            assert daemon._conn.execute('SELECT COUNT(*) FROM managed_states').fetchone()==(1,)
    asyncio.run(scenario())


def test_public_state_can_be_initialized_between_package_install_and_activation(tmp_path):
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    bundle,manifest,grants=resource_bundle('state.read/v1')
    async def scenario():
        authority=_authority(tmp_path)
        daemon=RuntimeDaemon(tmp_path,allow_insecure_credentials=os.name!='nt',
            trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
        await daemon.start()
        client=await connect(tmp_path,authority=authority)
        try:
            installed=await upload_install(client,authority,bundle,manifest)
            initial=await initialized(client,authority)
            await client.activate_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=installed.resource['harness_id'],
                composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
            await wait_refs(client,status='READY',serving=1)
            _,terminal,execution=await submit(client,authority,{'state_id':initial['state_id']})
            assert terminal['status']=='SUCCEEDED',terminal
            assert execution['state_snapshot'][initial['state_id']]==initial['state_revision_id']
        finally:
            await client.aclose(); await daemon.close()
    asyncio.run(scenario())
