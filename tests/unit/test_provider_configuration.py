"""Signed public profile approval, no credential material or Provider execution."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
import os
import uuid

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import CommandAuthority, ErrorCode, StableError, connect, decode_command, encode_command, sign_command
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex
from agent_meta_runtime.adapters.crypto import Ed25519KeyPair
from agent_meta_runtime.adapters.store.gc import collect_marks
from agent_meta_runtime.domain.ids import new_uuid7
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority
from test_provider_profile import profile_case

REALM='realm://main'
CAPABILITY='capability://example.model'


@asynccontextmanager
async def configured_environment(root, *, declared=True, profile_changes=None, ready_data=False, mode='CONTROLLED_TEST_ONLY', egress_changes=None, controlled_provider_test_ca=None, provider_normalizer='default'):
    run_init(root,insecure_dev_credential_file=os.name!='nt')
    reference,blobs,_,_=profile_case(tokenizer=ready_data,pricing=ready_data,profile_changes=profile_changes,mode=mode,egress_changes=egress_changes)
    bundle,manifest,grants=live_bundle(controlled_provider=True,provider_declaration=(reference,blobs) if declared else None,provider_normalizer=provider_normalizer)
    if not declared:
        bundle.blobs.update(blobs)
    publisher=sha256_hex(bundle.key.public_key().public_bytes_raw())
    daemon=RuntimeDaemon(root,allow_insecure_credentials=os.name!='nt',trusted_publishers=[publisher],controlled_provider_test_ca=controlled_provider_test_ca)
    await daemon.start()
    authority=_authority(root)
    client=await connect(root,authority=authority)
    try:
        installed=await upload_install(client,authority,bundle,manifest)
        handle='credential://'+('windows-dpapi/' if os.name=='nt' else 'insecure-dev/')+str(uuid.uuid4())
        kwargs=dict(realm_id=REALM,actor_id=authority.actor_id,harness_id=installed.resource['harness_id'],
            capability_id=CAPABILITY,profile_artifact_id=reference,credential_handle=handle)
        yield daemon,client,authority,kwargs,bundle,manifest,grants
    finally:
        await client.aclose()
        await daemon.close()


def test_signed_approval_is_secretless_revisioned_and_does_not_activate_or_execute(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            counts={table:daemon._conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                for table in ('tasks','invocations','effect_intents','capability_instances','compositions','authority_grants','authority_uses')}
            envelope=await client.prepare_harness_provider_configuration(**kwargs)
            result=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
            assert result.resource['configuration_revision']==1
            installation=await client.get_harness(kwargs['harness_id'])
            profile=installation['provider_configuration']
            assert profile['credential_handle']==kwargs['credential_handle'] and profile['profile_artifact_id']==kwargs['profile_artifact_id']
            assert profile['configuration_fact_id']==result.resource['configuration_fact_id']
            assert installation['status']=='INSTALLED' and profile['enabled']
            assert len(profile['verified_artifact_ids'])==2
            for table,count in counts.items():
                assert daemon._conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==count+int(table=='authority_uses')
            before=daemon._conn.execute('SELECT COUNT(*) FROM facts').fetchone()[0]
            replay=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
            assert replay==result
            assert daemon._conn.execute('SELECT COUNT(*) FROM facts').fetchone()[0]==before
            disabled=await client.configure_harness_provider(**kwargs,enabled=False)
            assert disabled.resource['configuration_revision']==2
            assert not (await client.get_harness(kwargs['harness_id']))['provider_configuration']['enabled']
    asyncio.run(run())


@pytest.mark.parametrize('kind',['configuration','meta','missing_meta'])
def test_stale_or_missing_guards_cannot_rebind_credentials(tmp_path,kind):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            first=await client.prepare_harness_provider_configuration(**kwargs)
            await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',first)
            if kind=='configuration':
                raw=await client.prepare_harness_provider_configuration(**kwargs,expected_configuration_revision=0)
            elif kind=='meta':
                raw=await client.prepare_harness_provider_configuration(**kwargs,expected_meta_revision=0)
            else:
                envelope=decode_command(await client.prepare_harness_provider_configuration(**kwargs))
                raw=encode_command(sign_command(replace(envelope,expected_meta_revision=None,auth_nonce=None,auth_issued_at_us=None,auth_signature=None),authority))
            before=daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]
            with pytest.raises(StableError) as caught:
                await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',raw)
            assert caught.value.code==(ErrorCode.INVALID_ARGUMENT if kind=='missing_meta' else ErrorCode.REVISION_CONFLICT)
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]==before
    asyncio.run(run())


@pytest.mark.parametrize('kind',['undeclared','different_profile','different_capability','raw_secret'])
def test_operator_signature_does_not_bypass_signed_package_binding_or_handle_shape(tmp_path,kind):
    async def run():
        async with configured_environment(tmp_path,declared=kind!='undeclared') as (daemon,client,authority,kwargs,*_):
            if kind=='different_profile':
                kwargs['profile_artifact_id']='artifact://sha256/'+'a'*64
            elif kind=='different_capability':
                kwargs['capability_id']='capability://different.model'
            elif kind=='raw_secret':
                kwargs['credential_handle']='synthetic-plaintext-must-not-be-persisted'
            with pytest.raises(StableError) as caught:
                await client.configure_harness_provider(**kwargs)
            assert caught.value.code==(ErrorCode.INVALID_ARGUMENT if kind=='raw_secret' else ErrorCode.AUTHORITY_DENIED)
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]==0
            assert not any(b'synthetic-plaintext-must-not-be-persisted' in bytes(row[0]) for row in daemon._conn.execute('SELECT payload_json FROM facts'))
    asyncio.run(run())


@pytest.mark.parametrize('permission',['model.invoke','harness.activate','correctly_scoped_activation'])
def test_unrelated_or_incorrectly_scoped_grant_cannot_configure_a_provider(tmp_path,permission):
    async def run():
        async with configured_environment(tmp_path) as (daemon,root,authority,kwargs,*_):
            key=Ed25519KeyPair.generate()
            principal=(await root.create_principal(realm_id=REALM,actor_id=authority.actor_id,kind='AGENT',
                public_key=key.public_bytes_raw())).resource['principal_id']
            target={'type':'CAPABILITY','id':CAPABILITY} if permission=='model.invoke' else {'type':'HARNESS',
                'id':kwargs['harness_id'] if permission=='correctly_scoped_activation' else 'harness://'+new_uuid7()}
            grant=(await root.delegate_authority(realm_id=REALM,actor_id=authority.actor_id,subject_id=principal,
                permissions=['harness.activate' if permission=='correctly_scoped_activation' else permission],scope={'realm_id':REALM,'targets':[target]})).resource['grant_id']
            actor=await connect(tmp_path,authority=CommandAuthority(principal,grant,key.sign))
            try:
                with pytest.raises(StableError) as caught:
                    await actor.configure_harness_provider(**{**kwargs,'actor_id':principal})
                assert caught.value.code==ErrorCode.AUTHORITY_DENIED
                assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]==0
            finally:
                await actor.aclose()
    asyncio.run(run())


def test_configuration_and_original_command_receipt_survive_actual_daemon_restart(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,bundle,*_):
            envelope=await client.prepare_harness_provider_configuration(**kwargs)
            original=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
            await client.aclose(); await daemon.close()
            restored=RuntimeDaemon(tmp_path,allow_insecure_credentials=os.name!='nt',
                trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
            await restored.start()
            after=await connect(tmp_path,authority=authority)
            try:
                before=restored._conn.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0]
                replay=await after.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
                assert replay==original
                assert restored._conn.execute('SELECT COUNT(*) FROM authority_uses').fetchone()[0]==before
                assert (await after.get_harness(kwargs['harness_id']))['provider_configuration']['configuration_fact_id']==original.resource['configuration_fact_id']
            finally:
                await after.aclose(); await restored.close()
    asyncio.run(run())


def test_task_acceptance_freezes_the_exact_configuration_fact_and_gc_pins_the_closure(tmp_path):
    async def run():
        async with configured_environment(tmp_path,ready_data=True) as (daemon,client,authority,kwargs,bundle,_,grants):
            original=await client.configure_harness_provider(**kwargs)
            configuration=(await client.get_harness(kwargs['harness_id']))['provider_configuration']
            assert len(configuration['verified_artifact_ids'])==4
            assert all(ref.rsplit('/',1)[1] in collect_marks(daemon._conn) for ref in configuration['verified_artifact_ids'])
            await client.activate_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=kwargs['harness_id'],
                composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
            await wait_refs(client,status='READY',serving=1)
            artifact=await client.put_artifact(realm_id=REALM,actor_id=authority.actor_id,content=canonical_json('freeze configuration'),kind='task_input',media_type='application/json')
            first=await client.submit_task(realm_id=REALM,actor_id=authority.actor_id,input_artifact_id=artifact['artifact_id'])
            await client.wait_task(first.task_id,timeout_s=10)
            execution=await client.get_task_execution(first.task_id)
            frozen=await client.get_artifact_content(execution['acceptance_view_artifact_id'])
            assert json.loads(frozen)['provider_configuration_fact_id']==original.resource['configuration_fact_id']
            new_handle='credential://'+('windows-dpapi/' if os.name=='nt' else 'insecure-dev/')+str(uuid.uuid4())
            updated=await client.configure_harness_provider(**{**kwargs,'credential_handle':new_handle})
            assert await client.get_artifact_content(execution['acceptance_view_artifact_id'])==frozen
            second=await client.submit_task(realm_id=REALM,actor_id=authority.actor_id,input_artifact_id=artifact['artifact_id'])
            await client.wait_task(second.task_id,timeout_s=10)
            later=await client.get_task_execution(second.task_id)
            assert json.loads(await client.get_artifact_content(later['acceptance_view_artifact_id']))['provider_configuration_fact_id']==updated.resource['configuration_fact_id']
            assert execution['invocations']==later['invocations']==[]
    asyncio.run(run())


def test_uninstalled_package_cannot_be_reenabled_by_provider_configuration(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            await client.configure_harness_provider(**kwargs)
            await client.uninstall_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=kwargs['harness_id'])
            with pytest.raises(StableError) as caught:
                await client.configure_harness_provider(**kwargs)
            assert caught.value.code==ErrorCode.FAILED_PRECONDITION
            assert (await client.get_harness(kwargs['harness_id']))['status']=='UNINSTALLED'
    asyncio.run(run())


def test_signed_credential_binding_cannot_be_substituted_after_operator_approval(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            original=decode_command(await client.prepare_harness_provider_configuration(**kwargs))
            altered={**original.payload,'credential_handle':kwargs['credential_handle'][:-1]+('0' if kwargs['credential_handle'][-1]!='0' else '1')}
            forged=encode_command(replace(original,payload=altered))
            with pytest.raises(StableError) as caught:
                await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',forged)
            assert caught.value.code==ErrorCode.AUTHORITY_DENIED
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]==0
    asyncio.run(run())


def test_public_egress_profile_cannot_approve_an_insecure_credential_handle(tmp_path):
    async def run():
        async with configured_environment(tmp_path,mode='PUBLIC_HTTPS') as (daemon,client,authority,kwargs,*_):
            with pytest.raises(StableError) as caught:
                await client.configure_harness_provider(**{**kwargs,'credential_handle':'credential://insecure-dev/'+str(uuid.uuid4())})
            assert caught.value.code==ErrorCode.FAILED_PRECONDITION
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_configured'").fetchone()[0]==0
    asyncio.run(run())


def test_approved_unready_profile_still_fails_before_any_model_reservation(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,bundle,_,grants):
            await client.configure_harness_provider(**kwargs)
            await client.activate_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=kwargs['harness_id'],
                composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
            await wait_refs(client,status='READY',serving=1)
            artifact=await client.put_artifact(realm_id=REALM,actor_id=authority.actor_id,content=canonical_json('approved unready profile'),kind='task_input',media_type='application/json')
            task=await client.submit_task(realm_id=REALM,actor_id=authority.actor_id,input_artifact_id=artifact['artifact_id'])
            terminal,done=await client.wait_task(task.task_id,timeout_s=10)
            assert done and terminal['error']==ErrorCode.FAILED_PRECONDITION
            assert (await client.get_task_execution(task.task_id))['invocations']==[]
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_cost_reserved'").fetchone()[0]==0
    asyncio.run(run())
