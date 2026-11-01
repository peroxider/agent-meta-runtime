"""Application control-flow port tests; no configured/live Provider claim."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from agent_meta_runtime.application.task_host import TaskSession
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.provider_accounting import ProviderReservation
from agent_meta_runtime.domain.provider_transport import ProviderEgressPolicy, ProviderHttpRequest
from agent_meta_runtime.ports.host_execution import HostCallValue, PreparedProviderCall
from agent_meta_runtime.sdk import ErrorCode, StableError
from agent_meta_runtime.sdk.host import (ContextProjection, HarnessAdapter, ModelResponse, ProjectionManifest,
    ProviderAdapter, ProviderRequestPlan, ProviderTerminalResponse, ProviderUsage, Section, SourceRef, TextPart,
    terminal_result)
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex

REF = "artifact://sha256/" + "a"*64
OTHER = "artifact://sha256/" + "b"*64
BODY = canonical_json({"model":"synthetic-model","messages":[{"role":"user","content":"synthetic"}],"max_tokens":8,"stream":False})


def session_case(*, wrong_profile=False, cancel_preflight=False, async_normalizer=False):
    cancelled, reserved, committed, normalized = [], [], [], []
    class Store:
        def check(self, task_id):
            if cancelled:
                raise asyncio.CancelledError()
        def read_artifact(self, ref):
            return b'{"type":"object"}'
        def reserve(self, task, **kwargs):
            reserved.append(kwargs)
            return {"invocation_id":"invocation://"+new_uuid7(),"replay":False}
        def finish_invocation(self, *args, **kwargs):
            raise AssertionError("generic activity path recommitted a Provider terminal")
    class LegacyRunner:
        async def invoke(self, **kwargs):
            raise AssertionError("Provider entered the legacy model activity runner")
    class Providers:
        def prepare(self, *, task, ordinal, plan, normalize, **kwargs):
            request = ProviderHttpRequest(task.task_id+'/invocation/'+str(ordinal),
                ProviderEgressPolicy('localhost',443,'/messages',('127.0.0.1/32',),'CONTROLLED_TEST_ONLY'),
                'synthetic-model','credential://synthetic-unused',plan.body,1_000_000)
            reservation = ProviderReservation(REF,REF,REF,request.scope_hash,3,8,40)
            if cancel_preflight:
                cancelled.append(True)
            return PreparedProviderCall(reservation,request,
                lambda raw: normalize(ProviderTerminalResponse(OTHER if wrong_profile else REF,raw)))
        async def invoke(self, *, prepared, **kwargs):
            try:
                value = prepared.normalize(b'{"complete":true}')
            except StableError as exc:
                value = HostCallValue(error_code=exc.code,raise_error=True)
            committed.append(value)
            return value
    async def noop(*args):
        pass
    def normalize(response):
        normalized.append(response)
        return ModelResponse((TextPart('normalized'),),'STOP',ProviderUsage(3,2,25))
    async def normalize_async(response):
        return normalize(response)
    adapter = HarnessAdapter(noop,None,{},noop,provider=ProviderAdapter(lambda request:ProviderRequestPlan(REF,BODY),
        normalize_async if async_normalizer else normalize))
    operation = {"operation_id":"fixture.model","effects":["model.invoke"],"required_permissions":["model.invoke"],
        "input_schema_artifact_id":REF,"output_schema_artifact_id":REF}
    task = SimpleNamespace(task_id='task://'+new_uuid7(),root_action_id='action://'+new_uuid7(),
        capability_surface_content=canonical_json({"operations":[{"operation_id":"fixture.model"}]}))
    bound = SimpleNamespace(adapter=adapter,composition={"slots":{"model":{"capability_id":"capability://model","descriptor_revision":1}}},
        descriptors={("capability://model",1):{"capability_id":"capability://model","operations":[operation]}})
    manifest = ProjectionManifest('context://projection/'+new_uuid7(),REF,'composition://'+new_uuid7(),1,
        (SourceRef('artifact',REF,'a'*64),),(Section('system',REF,REF,1),),REF,'synthetic/v1',1,100)
    projection = ContextProjection(manifest,'artifact://sha256/'+sha256_hex(b'x'),b'x')
    session = TaskSession(Store(),task,bound,LegacyRunner(),Providers())
    session._projections[manifest.projection_id] = projection
    return session,projection,reserved,committed,normalized


def test_provider_shares_normalized_terminal_pipeline_without_generic_double_commit():
    session,projection,reserved,committed,normalized = session_case()
    async def run():
        response = await session.invoke_model(projection)
        assert session.validate_terminal(terminal_result(response))
        assert response.usage.cost_microunits == 25
    asyncio.run(run())
    assert len(reserved)==len(committed)==len(normalized)==1
    request = json.loads(reserved[0]['content'])
    assert request['schema']=='host-model-request/v2'
    assert request['provider_plan']=={'profile_artifact_id':REF,'body_sha256':sha256_hex(BODY)}
    assert reserved[0]['provider'].maximum_cost_microunits==40
    assert session._models==1 and not session._pending


@pytest.mark.parametrize('case',[{'wrong_profile':True},{'async_normalizer':True}])
def test_invalid_provider_normalizer_never_advances_model_or_tool_dispatch(case):
    session,projection,reserved,committed,normalized = session_case(**case)
    async def run():
        with pytest.raises(StableError) as caught:
            await session.invoke_model(projection)
        assert caught.value.code==ErrorCode.INVALID_RESULT
    asyncio.run(run())
    assert len(reserved)==len(committed)==1 and not normalized
    assert session._models==0 and not session._pending and not session._history


def test_cancel_during_root_preflight_prevents_all_admission_and_execution():
    session,projection,reserved,committed,normalized = session_case(cancel_preflight=True)
    async def run():
        with pytest.raises(asyncio.CancelledError):
            await session.invoke_model(projection)
    asyncio.run(run())
    assert not reserved and not committed and not normalized and session._ordinal==0
