"""Real signed approvals and atomic Root admission; no upstream request."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
import uuid
from types import SimpleNamespace

import pytest

from agent_meta_runtime.adapters.provider_host import ProviderHostCalls
from agent_meta_runtime.adapters.credentials import service_signing_authority
from agent_meta_runtime.adapters.store.provider_admission import frozen_configuration
from agent_meta_runtime.adapters.store.provider_accounting import read_provider
from agent_meta_runtime.adapters.store.service_certificates import load_service_execution_trust
from agent_meta_runtime.domain.canonical import canonical_json, now_us
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.provider_accounting import ProviderReservation
from agent_meta_runtime.domain.provider_profile import load_profile
from agent_meta_runtime.domain.provider_transport import ProviderHttpRequest
from agent_meta_runtime.sdk.host import ProviderRequestPlan

from test_bound_harness import wait_refs
from test_provider_configuration import configured_environment, CAPABILITY, REALM


@asynccontextmanager
async def admitted_environment(root, *, approve=True):
    async with configured_environment(root,ready_data=True) as (daemon,client,authority,kwargs,bundle,_,grants):
        if approve:
            await client.configure_harness_provider(**kwargs)
        await client.activate_harness(realm_id=REALM,actor_id=authority.actor_id,harness_id=kwargs['harness_id'],
            composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
        await wait_refs(client,status='READY',serving=1)
        # Keep the actual accepted Task running under direct Root store control.
        # The public daemon still refuses configured model execution by default.
        daemon._task_host.stopping=True
        await daemon._task_host_task
        artifact=await client.put_artifact(realm_id=REALM,actor_id=authority.actor_id,content=canonical_json('synthetic admitted Task'),kind='task_input',media_type='application/json')
        accepted=await client.submit_task(realm_id=REALM,actor_id=authority.actor_id,input_artifact_id=artifact['artifact_id'],
            budget={'max_cost_microunits':1000})
        store=daemon._task_host.store
        store.start(accepted.task_id)
        composition=store.check(accepted.task_id).serving_composition_id
        bound=daemon._catalog.binding(composition)
        task=store.envelope(accepted.task_id,bound)
        slot=bound.composition['slots']['model']
        operation=next(op for op in bound.descriptors[(CAPABILITY,slot['descriptor_revision'])]['operations'] if op['operation_id']=='example.model')
        profile,_=load_profile(kwargs['profile_artifact_id'],store.read_artifact)
        body=canonical_json({'model':profile.model_id,'messages':[{'role':'user','content':'synthetic'}],'max_tokens':8,'stream':False})
        request=ProviderHttpRequest(task.task_id+'/invocation/0',profile.policy,profile.model_id,kwargs['credential_handle'],
            body,profile.timeout_us,profile.maximum_response_bytes,now_us()+4_000_000)
        tokens,output,cost=profile.preflight(ProviderRequestPlan(profile.artifact_id,body))
        fact=json.loads(task.acceptance_view_content).get('provider_configuration_fact_id')
        reservation=ProviderReservation(profile.artifact_id,profile.price_policy_artifact_id,profile.tokenizer_artifact_id,
            request.scope_hash,tokens,output,cost,fact or 'fact://'+new_uuid7(),request.deadline_at_us)
        yield SimpleNamespace(daemon=daemon,client=client,authority=authority,kwargs=kwargs,store=store,task=task,
            operation=operation,request=request,reservation=reservation)


def reserve(case, *, reservation=None, request=None):
    return case.store.reserve(case.task,ordinal=0,kind='MODEL',capability_id=CAPABILITY,operation=case.operation,
        content=b'{"synthetic":"bounded input"}',provider=reservation or case.reservation,provider_request=request or case.request)


def counts(case):
    conn=case.daemon._conn
    return tuple(conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('invocations','authority_uses'))+(
        conn.execute("SELECT COUNT(*) FROM facts WHERE event_type='provider_cost_reserved'").fetchone()[0],
        conn.execute('SELECT consumed_budget_json FROM tasks WHERE task_id=?',(case.task.task_id,)).fetchone()[0])


def test_configuration_reservation_commits_exact_fact_deadline_and_independent_maximum(tmp_path):
    async def run():
        async with admitted_environment(tmp_path) as case:
            result=reserve(case)
            raw=case.daemon._conn.execute('SELECT backend_ref_json FROM invocations WHERE invocation_id=?',(result['invocation_id'],)).fetchone()[0]
            assert read_provider(case.daemon._conn,result['invocation_id'],json.loads(raw))['reservation']==case.reservation.document()
            assert case.reservation.document()['schema']=='provider-reservation/v2'
            assert case.reservation.maximum_cost_microunits==170
    asyncio.run(run())


@pytest.mark.parametrize('change',['cost','input','output','profile','price','tokenizer','configuration','deadline','missing_request','request_id','handle','policy'])
def test_substituted_preparation_cannot_debit_any_authority_or_budget(tmp_path,change):
    async def run():
        async with admitted_environment(tmp_path) as case:
            reservation,request=case.reservation,case.request
            if change in ('cost','input','output'):
                field={'cost':'maximum_cost_microunits','input':'input_tokens','output':'maximum_output_tokens'}[change]
                reservation=replace(reservation,**{field:getattr(reservation,field)-1})
            elif change in ('profile','price','tokenizer'):
                field={'profile':'profile_artifact_id','price':'pricing_artifact_id','tokenizer':'tokenizer_artifact_id'}[change]
                reservation=replace(reservation,**{field:'artifact://sha256/'+'a'*64})
            elif change=='configuration':
                reservation=replace(reservation,configuration_fact_id='fact://'+new_uuid7())
            elif change=='deadline':
                reservation=replace(reservation,deadline_at_us=request.deadline_at_us+1)
            elif change=='request_id':
                request=replace(request,request_id=case.task.task_id+'/invocation/1')
            elif change=='handle':
                request=replace(request,credential_handle=request.credential_handle.rsplit('/',1)[0]+'/'+str(uuid.uuid4()))
                reservation=replace(reservation,request_hash=request.scope_hash)
            elif change=='policy':
                request=replace(request,policy=replace(request.policy,path='/different'))
                reservation=replace(reservation,request_hash=request.scope_hash)
            before=counts(case)
            with pytest.raises(StableError) as caught:
                if change=='missing_request':
                    case.store.reserve(case.task,ordinal=0,kind='MODEL',capability_id=CAPABILITY,operation=case.operation,
                        content=b'{}',provider=reservation)
                else:
                    reserve(case,reservation=reservation,request=request)
            assert caught.value.code==ErrorCode.AUTHORITY_DENIED
            assert counts(case)==before
    asyncio.run(run())


@pytest.mark.parametrize('mode',['disable','rotate','late_approval'])
def test_old_task_cannot_borrow_newer_approval_before_reservation(tmp_path,mode):
    async def run():
        async with admitted_environment(tmp_path,approve=mode!='late_approval') as case:
            options={'enabled':False} if mode=='disable' else {'credential_handle':case.kwargs['credential_handle'].rsplit('/',1)[0]+'/'+str(uuid.uuid4())} if mode=='rotate' else {}
            await case.client.configure_harness_provider(**{**case.kwargs,**options})
            before=counts(case)
            with pytest.raises(StableError) as caught:
                reserve(case)
            assert caught.value.code==(ErrorCode.FAILED_PRECONDITION if mode=='late_approval' else ErrorCode.AUTHORITY_DENIED)
            assert counts(case)==before
    asyncio.run(run())


@pytest.mark.parametrize('mode',['disable','rotate'])
def test_configuration_change_after_reservation_is_not_sent_and_does_not_refund_call_count(tmp_path,mode):
    async def run():
        async with admitted_environment(tmp_path) as case:
            invocation=reserve(case)['invocation_id']
            await case.client.configure_harness_provider(**{**case.kwargs,**({'enabled':False} if mode=='disable' else {
                'credential_handle':case.kwargs['credential_handle'].rsplit('/',1)[0]+'/'+str(uuid.uuid4())})})
            calls=[]
            class Worker:
                session_id='provider-test/no-native-process'
                async def run(self,*args,**kwargs):
                    calls.append(True)
                    raise AssertionError('changed approval reached the worker')
            trust=load_service_execution_trust(case.daemon._conn,case.store.catalog.cas,realm_id=REALM,now_us=now_us())
            signer=service_signing_authority(tmp_path,expected_public_key=trust.service_public_key,allow_insecure=case.daemon._allow_insecure)
            edge=ProviderHostCalls(case.store,worker=Worker(),trust=trust,epoch_id=json.loads(case.task.acceptance_view_content)['epoch_id'],signer=signer)
            with pytest.raises(StableError) as caught:
                await edge.invoke(task=case.task,invocation_id=invocation,request=case.request,required_permissions={'model.invoke'},normalize=lambda _:None)
            assert caught.value.code==ErrorCode.AUTHORITY_DENIED and calls==[]
            journal=json.loads(case.daemon._conn.execute('SELECT backend_ref_json FROM invocations WHERE invocation_id=?',(invocation,)).fetchone()[0])
            assert read_provider(case.daemon._conn,invocation,journal)['settlement']['outcome']=='NOT_SENT'
            consumed=json.loads(case.daemon._conn.execute('SELECT consumed_budget_json FROM tasks WHERE task_id=?',(case.task.task_id,)).fetchone()[0])
            assert consumed['model_calls']==consumed['effects']==1 and consumed['cost_microunits']==0
    asyncio.run(run())


def test_confirmed_replay_remains_available_after_disable_without_new_invocation_grant_use(tmp_path):
    async def run():
        async with admitted_environment(tmp_path) as case:
            invocation=reserve(case)['invocation_id']
            case.store.finish_invocation(invocation,content=b'{"synthetic":"confirmed"}',
                usage={'input_tokens':52,'output_tokens':1,'cost_microunits':135},provider_outcome='CONFIRMED')
            await case.client.configure_harness_provider(**case.kwargs,enabled=False)
            before=counts(case)
            uses=case.daemon._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE use_kind='host_invocation'").fetchone()[0]
            replay=reserve(case)
            assert replay['replay'] and replay['invocation_id']==invocation
            assert counts(case)[::2]==before[::2] and counts(case)[3]==before[3]
            assert case.daemon._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE use_kind='host_invocation'").fetchone()[0]==uses
            frozen=frozen_configuration(case.store,case.task,CAPABILITY,require_current=False)
            assert frozen['configuration_fact_id']==case.reservation.configuration_fact_id
    asyncio.run(run())
