"""Public Meta resource DTO boundaries; no claim of installed consumer proof."""
from dataclasses import FrozenInstanceError

import pytest

from agent_meta_runtime.sdk.host import (ArtifactPut, ArtifactRead, StateRead, StateWrite,
    ResourceReceipt, ResourceAdapter, HarnessAdapter, InvocationResult)
from agent_meta_runtime.sdk.packages import sha256_hex
from agent_meta_runtime.domain.resource_contract import resource_request_document, validate_resource_operation

CONTENT = b'{"value":1}'
ARTIFACT = 'artifact://sha256/' + sha256_hex(CONTENT)
STATE = 'state://01900000-0000-7000-8000-000000000000'
REVISION = 'state-revision://01900000-0000-7000-8000-000000000001'


def test_resource_values_expose_no_live_authority_and_preserve_content_hashes():
    plans = [ArtifactRead(ARTIFACT), ArtifactPut('note','application/json',CONTENT),
        StateRead(STATE), StateWrite(STATE,REVISION,ARTIFACT)]
    assert {resource_request_document(plan)['schema'] for plan in plans} == {
        'artifact.read/v1','artifact.put/v1','state.read/v1','state.write/v1'}
    assert 'content' not in resource_request_document(plans[1])
    receipt = ResourceReceipt('state.read/v1', ARTIFACT,'application/json',CONTENT,STATE,REVISION)
    assert receipt.content == CONTENT
    for value in [*plans, receipt]:
        assert not any(hasattr(value,name) for name in ('conn','store','credential','authority','__dict__'))
    with pytest.raises(FrozenInstanceError):
        receipt.content = b'changed'


@pytest.mark.parametrize('factory', [
    lambda: ArtifactRead('file://local'), lambda: ArtifactRead(None),
    lambda: ArtifactPut('bad-kind','application/json',b'{}'),
    lambda: ArtifactPut('note','application/octet-stream',b'bytes'),
    lambda: ArtifactPut('note','application/json',bytearray(b'{}')),
    lambda: ArtifactPut('note','application/json',b'x'*(1024*1024+1)),
    lambda: StateRead('capability://wrong'), lambda: StateRead(None),
    lambda: StateWrite(STATE,'state://wrong',ARTIFACT),
    lambda: StateWrite(STATE,REVISION,'path://wrong'),
    lambda: ResourceReceipt({},ARTIFACT,'application/json',CONTENT),
    lambda: ResourceReceipt('artifact.read/v1',ARTIFACT,'application/json',b'wrong'),
    lambda: ResourceReceipt('artifact.read/v1',ARTIFACT,'application/json',CONTENT,STATE,REVISION),
    lambda: ResourceReceipt('state.read/v1',ARTIFACT,'application/json',CONTENT),
    lambda: ResourceAdapter(None,lambda value: value),
])
def test_unknown_mutable_oversized_and_ambiguous_resource_values_fail_closed(factory):
    with pytest.raises(ValueError):
        factory()


def test_resource_callbacks_cannot_shadow_ordinary_tool_bindings():
    async def callback(*args):
        pass
    adapter = ResourceAdapter(lambda value: ArtifactRead(ARTIFACT), lambda value: InvocationResult(content=CONTENT))
    value = HarnessAdapter(callback, callback, {}, callback, resource_tools={'read':adapter})
    assert value.resource_tools['read'] is adapter
    with pytest.raises(ValueError):
        HarnessAdapter(callback,callback,{'read':callback},callback,resource_tools={'read':adapter})
    with pytest.raises(ValueError):
        HarnessAdapter(callback,callback,{},callback,resource_tools={'read':callback})


@pytest.mark.parametrize('mutation', [
    {'resource_contract':'unknown/v1'}, {'resource_contract':[]}, {'idempotency':'PURE'},
    {'effects':['none']}, {'required_permissions':[]},
])
def test_resource_descriptor_cannot_weaken_effects_authority_or_idempotency(mutation):
    operation = {'resource_contract':'state.write/v1','idempotency':'KEYED','effects':['state.write'],
        'required_permissions':['state.write'], **mutation}
    with pytest.raises(ValueError):
        validate_resource_operation(operation)
