"""Actual public operator CLI validation/approval; synthetic provisioned items."""

import asyncio
import json
import os

import pytest

from agent_meta_runtime.adapters.provider_credentials import provision_provider_credential
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.cli.main import main
from test_provider_configuration import configured_environment

SECRET=b'synthetic-operator-cli-provider-credential'


def counts(conn):
    return tuple(conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
        for table in ('commands','authority_uses','facts','tasks','invocations'))


def cli_args(root,kwargs,*,dry_run=False):
    return ['--data-dir',str(root),'--output','json',
        *(['--insecure-dev-credential-file'] if os.name!='nt' else []),*(['--dry-run'] if dry_run else []),
        'harness','configure-provider',kwargs['harness_id'],'--capability',kwargs['capability_id'],
        '--profile-artifact',kwargs['profile_artifact_id'],'--credential-handle',kwargs['credential_handle']]


def test_signed_validation_query_never_claims_commands_or_uses_and_original_plan_can_execute(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            envelope=await client.prepare_harness_provider_configuration(**kwargs)
            before=counts(daemon._conn)
            first=await client.validate_harness_provider_configuration(envelope)
            assert await client.validate_harness_provider_configuration(envelope)==first
            assert counts(daemon._conn)==before
            assert first['valid'] and not first['will_execute_model']
            assert first['required_principal']=='CURRENT_EPOCH_ROOT_OPERATOR'
            assert first['profile']['model_id']=='synthetic-model' and first['profile']['currency'] is None
            result=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
            assert result.resource['configuration_revision']==1
    asyncio.run(run())


def test_operator_cli_dry_run_previews_exact_profile_and_only_handle_then_public_commit(tmp_path,capsys):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            item=provision_provider_credential(tmp_path,bytearray(SECRET),allow_insecure=os.name!='nt')
            kwargs={**kwargs,'credential_handle':item['credential_handle']}
            before=counts(daemon._conn)
            assert await asyncio.to_thread(main,cli_args(tmp_path,kwargs,dry_run=True))==0
            output=capsys.readouterr()
            assert SECRET.decode() not in output.out+output.err
            preview=json.loads(output.out)['result']
            assert preview['dry_run'] and preview['valid'] and not preview['will_execute_model']
            assert preview['profile']['destination']['host']=='localhost'
            assert preview['configuration']['credential_handle']==item['credential_handle']
            assert counts(daemon._conn)==before
            result=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',preview['command_envelope_jcs'])
            assert result.resource['configuration_revision']==1
            assert await asyncio.to_thread(main,[*cli_args(tmp_path,kwargs),'--disable'])==0
            disabled=json.loads(capsys.readouterr().out)['result']
            assert disabled['configuration_revision']==2
            assert not (await client.get_harness(kwargs['harness_id']))['provider_configuration']['enabled']
    asyncio.run(run())


def test_cli_actual_approval_uses_public_api_and_does_not_execute_a_model(tmp_path,capsys):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            assert await asyncio.to_thread(main,cli_args(tmp_path,kwargs))==0
            result=json.loads(capsys.readouterr().out)['result']
            assert result['configuration_revision']==1
            assert (await client.get_harness(kwargs['harness_id']))['provider_configuration']['configuration_fact_id']==result['configuration_fact_id']
            assert daemon._conn.execute('SELECT COUNT(*) FROM invocations').fetchone()[0]==0
    asyncio.run(run())


def test_raw_token_in_handle_argument_is_rejected_before_dry_run_can_print_a_plan(tmp_path,capsys):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            before=counts(daemon._conn)
            assert await asyncio.to_thread(main,cli_args(tmp_path,{**kwargs,'credential_handle':SECRET.decode()},dry_run=True))==2
            output=capsys.readouterr()
            assert SECRET.decode() not in output.out+output.err
            assert json.loads(output.out)['error']['code']==ErrorCode.INVALID_ARGUMENT
            assert counts(daemon._conn)==before
    asyncio.run(run())


def test_validation_refuses_stale_guards_without_claiming_or_rebinding(tmp_path):
    async def run():
        async with configured_environment(tmp_path) as (daemon,client,authority,kwargs,*_):
            prepared=await client.prepare_harness_provider_configuration(**kwargs)
            await client.configure_harness_provider(**kwargs)
            before=counts(daemon._conn)
            with pytest.raises(StableError) as caught:
                await client.validate_harness_provider_configuration(prepared)
            assert caught.value.code==ErrorCode.REVISION_CONFLICT
            assert counts(daemon._conn)==before
    asyncio.run(run())
