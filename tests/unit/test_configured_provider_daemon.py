"""Signed package/approval/IPC -> native owned worker -> synthetic local TLS.

Explicit loopback TEST Host profile only, never paid/live or Managed proof.
"""

import asyncio
import json

import pytest

from agent_meta_runtime.adapters.provider_credentials import provision_provider_credential
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.errors import ErrorCode
from agent_meta_runtime.domain.host_profile import CONTROLLED_PROVIDER_HOST_PROFILE_HASH
from agent_meta_runtime.sdk.host import decode_model_response

from test_bound_harness import wait_refs
from test_provider_configuration import configured_environment, REALM
from test_provider_https import edge, SECRET


@pytest.mark.parametrize('mode',['success','unknown_usage','overrun','disconnect','missing_credential','zero_claim','invalid_normalizer','cancel'])
def test_public_task_uses_frozen_approval_and_root_wire_pricing(tmp_path,edge,mode):
    server,_,_,_,_,_,ca,_=edge
    server.mode='disconnect' if mode=='disconnect' else 'hold' if mode=='cancel' else 'messages'
    message={'id':'msg-synthetic','type':'message','role':'assistant','model':'synthetic-model',
        'content':[{'type':'text','text':'synthetic terminal'}],'stop_reason':'end_turn','stop_sequence':None}
    if mode!='unknown_usage':
        message['usage']={'input_tokens':52,'output_tokens':2 if mode=='overrun' else 1}
    server.message_response=canonical_json(message)
    async def run():
        async with configured_environment(tmp_path/'runtime',ready_data=True,
                egress_changes={'port':server.server_port,'networks':['127.0.0.1/32','::1/128']},
                controlled_provider_test_ca=ca,
                provider_normalizer='invalid' if mode=='invalid_normalizer' else 'zero_claim' if mode=='zero_claim' else 'default') as (daemon,client,authority,kwargs,bundle,_,grants):
            if mode!='missing_credential':
                item=provision_provider_credential(daemon.data_dir,bytearray(SECRET),allow_insecure=daemon._allow_insecure)
                kwargs={**kwargs,'credential_handle':item['credential_handle']}
            configured=await client.configure_harness_provider(**kwargs)
            await client.activate_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=kwargs['harness_id'],
                composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
            await wait_refs(client,status='READY',serving=1)
            assert daemon.status()['provider_execution']=='CONTROLLED_TEST_ONLY'
            artifact=await client.put_artifact(realm_id=REALM,actor_id=authority.actor_id,content=canonical_json('synthetic Provider task'),kind='task_input',media_type='application/json')
            accepted=await client.submit_task(realm_id=REALM,actor_id=authority.actor_id,input_artifact_id=artifact['artifact_id'],budget={'max_cost_microunits':1000})
            if mode=='cancel':
                async with asyncio.timeout(5):
                    while not server.seen:
                        await asyncio.sleep(.005)
                await client.cancel_task(realm_id=REALM,actor_id=authority.actor_id,task_id=accepted.task_id)
            terminal,done=await client.wait_task(accepted.task_id,timeout_s=10)
            assert done
            execution=await client.get_task_execution(accepted.task_id)
            view=json.loads(await client.get_artifact_content(execution['acceptance_view_artifact_id']))
            assert view['backend_profile_hash']==CONTROLLED_PROVIDER_HOST_PROFILE_HASH
            assert view['provider_configuration_fact_id']==configured.resource['configuration_fact_id']
            if mode=='missing_credential':
                assert terminal['error']==ErrorCode.KEY_UNAVAILABLE and execution['invocations']==[] and server.seen==[]
                assert daemon._providers._worker is None
                return
            assert len(server.seen)==len(execution['invocations'])==1
            row=daemon._conn.execute('SELECT backend_ref_json,usage_json,output_artifact_id FROM invocations WHERE action_id=(SELECT root_action_id FROM tasks WHERE task_id=?)',(accepted.task_id,)).fetchone()
            journal,usage=json.loads(row[0]),json.loads(row[1])
            assert journal['provider']['reservation']['configuration_fact_id']==configured.resource['configuration_fact_id']
            observation=daemon._providers._worker.observation(journal['request_id'])
            assert observation['exit_confirmed'] and observation['worker_pid']
            if mode in ('disconnect','cancel'):
                assert terminal['status']==('CANCELLED' if mode=='cancel' else 'FAILED_RECOVERY')
                assert usage['cost_microunits'] is None
                assert journal['provider']['settlement']['liability_microunits']==135
                assert journal['provider']['settlement']['outcome']=='UNKNOWN'
                server.release.set()
            elif mode=='overrun':
                assert terminal['error']==ErrorCode.RESOURCE_EXHAUSTED and usage['cost_microunits']==140
                assert journal['provider']['settlement']['overrun']
            elif mode=='invalid_normalizer':
                assert terminal['error']==ErrorCode.INVALID_RESULT and row[2] is None
                assert usage['cost_microunits']==135 and journal['provider']['settlement']['liability_microunits']==135
            else:
                assert terminal['status']=='SUCCEEDED'
                response=decode_model_response(await client.get_artifact_content(row[2]))
                assert response.usage.input_tokens==(None if mode=='unknown_usage' else 52)
                assert response.usage.cost_microunits==(None if mode=='unknown_usage' else 135)
                assert usage['cost_microunits']==response.usage.cost_microunits
            assert SECRET not in repr(daemon._conn.execute('SELECT payload_json FROM facts').fetchall()).encode()
    asyncio.run(run())
