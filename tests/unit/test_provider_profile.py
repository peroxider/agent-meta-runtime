"""Frozen profile data and Root-owned pricing; no model call or real tokenizer."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.provider_profile import ProviderPricing, load_profile
from agent_meta_runtime.sdk.host import ProviderRequestPlan
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex


def profile_case(*, tokenizer=True, pricing=True, mode='CONTROLLED_TEST_ONLY', profile_changes=None, price_changes=None, tokenizer_changes=None, egress_changes=None):
    blobs={}
    def add(value):
        raw=canonical_json(value)
        reference='artifact://sha256/'+sha256_hex(raw)
        blobs[reference]=raw
        return reference
    policy=add({'schema':'provider-egress/v1','scheme':'https','host':'localhost' if mode=='CONTROLLED_TEST_ONLY' else 'provider.example',
        'port':443,'path':'/messages','networks':['127.0.0.1/32'] if mode=='CONTROLLED_TEST_ONLY' else ['0.0.0.0/0'],'profile':mode,**(egress_changes or {})})
    token=add({'schema':'provider-tokenizer/v1','model_id':'synthetic-model','algorithm':'CONTROLLED_TEST_UTF8_BYTES_V1',
        'tokenizer_id':'utf8-bytes/v1',**(tokenizer_changes or {})}) if tokenizer else None
    price=add({'schema':'provider-price/v1','currency':'TEST','pricing_version':'synthetic-v1','rounding':'CEIL_EACH_DIMENSION_MICROUNIT',
        'input_microunits_per_million_tokens':2500000,'output_microunits_per_million_tokens':5000000,
        'minimum_cost_microunits':7,**(price_changes or {})}) if pricing else None
    reference=add({'schema':'provider-profile/v1','protocol':'anthropic-messages-terminal/v1','model_id':'synthetic-model',
        'parameter_allowlist':['max_tokens','messages','model','stream','system','tools'],
        'context_window_tokens':4096,'maximum_output_tokens':32,'maximum_request_bytes':65536,'maximum_response_bytes':65536,
        'timeout_us':5000000,'egress_policy_artifact_id':policy,'tokenizer_artifact_id':token,'price_policy_artifact_id':price,
        'lookup_policy':'UNAVAILABLE_NO_RETRY','usage_mapping':'anthropic-messages-usage/v1',**(profile_changes or {})})
    body=canonical_json({'model':'synthetic-model','messages':[{'role':'user','content':'synthetic'}],'max_tokens':8,'stream':False})
    return reference,blobs,ProviderRequestPlan(reference,body),add


def test_verified_closure_is_immutable_and_preflight_uses_explicit_test_tokenizer():
    ref,blobs,plan,_=profile_case()
    profile,closure=load_profile(ref,blobs.__getitem__)
    assert set(closure)==set(blobs) and len(closure)==4
    with pytest.raises(FrozenInstanceError):
        profile.model_id='different'
    tokens,output,cost=profile.preflight(plan)
    assert tokens==52 and output==8 and cost==170
    assert profile.policy.profile=='CONTROLLED_TEST_ONLY' and profile.pricing.currency=='TEST'


@pytest.mark.parametrize('tokenizer,pricing',[(False,True),(True,False),(False,False)])
def test_missing_tokenizer_or_price_is_unavailable_instead_of_free(tokenizer,pricing):
    ref,blobs,plan,_=profile_case(tokenizer=tokenizer,pricing=pricing)
    profile,_=load_profile(ref,blobs.__getitem__)
    with pytest.raises(StableError) as caught:
        profile.preflight(plan)
    assert caught.value.code==ErrorCode.FAILED_PRECONDITION


@pytest.mark.parametrize('mode,algorithm',[('PUBLIC_HTTPS','CONTROLLED_TEST_UTF8_BYTES_V1'),('CONTROLLED_TEST_ONLY','glm-exact-not-installed')])
def test_public_model_never_uses_fixture_tokenizer_or_an_unimplemented_algorithm(mode,algorithm):
    ref,blobs,plan,_=profile_case(mode=mode,tokenizer_changes={'algorithm':algorithm})
    profile,_=load_profile(ref,blobs.__getitem__)
    with pytest.raises(StableError) as caught:
        profile.preflight(plan)
    assert caught.value.code==ErrorCode.FAILED_PRECONDITION


def test_price_rounding_and_minimum_are_integer_exact_and_unknown_is_preserved():
    policy=ProviderPricing('TEST','v1',2500000,5000000,7)
    assert policy.cost(3,2)==18
    assert policy.cost(0,0)==7
    assert policy.cost(None,0) is None and policy.cost(0,None) is None
    with pytest.raises(StableError) as invalid:
        policy.cost(None,-1)
    assert invalid.value.code==ErrorCode.INVALID_RESULT
    with pytest.raises(StableError) as caught:
        policy.cost(2**53-1,2**53-1)
    assert caught.value.code==ErrorCode.RESOURCE_EXHAUSTED


@pytest.mark.parametrize('change',[{'input_microunits_per_million_tokens':True},{'minimum_cost_microunits':-1},
    {'rounding':'FLOOR'},{'currency':'usd'},{'maximum_cost':0}])
def test_invalid_or_unversioned_price_dimensions_are_refused(change):
    ref,blobs,_,_=profile_case(price_changes=change)
    with pytest.raises(StableError) as caught:
        load_profile(ref,blobs.__getitem__)
    assert caught.value.code==ErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize('change',[{'maximum_output_tokens':True},{'maximum_response_bytes':2**20+1},{'timeout_us':300000001},
    {'parameter_allowlist':['model','messages','max_tokens','stream']},{'lookup_policy':'AUTO_RETRY'},
    {'unknown_secret':'forbidden'},{'usage_mapping':'assume-zero'},{'context_window_tokens':0}])
def test_profile_shape_and_limits_are_closed(change):
    ref,blobs,_,_=profile_case(profile_changes=change)
    with pytest.raises(StableError):
        load_profile(ref,blobs.__getitem__)


@pytest.mark.parametrize('kind',['hash','missing'])
def test_missing_or_substituted_dependency_cannot_become_a_zero_cost_profile(kind):
    ref,blobs,_,_=profile_case()
    dependency=json.loads(blobs[ref])['price_policy_artifact_id']
    if kind=='hash':
        blobs[dependency]=b'{}'
    else:
        del blobs[dependency]
    with pytest.raises(StableError) as caught:
        load_profile(ref,blobs.__getitem__)
    assert caught.value.code==(ErrorCode.INTEGRITY_ERROR if kind=='hash' else ErrorCode.FAILED_PRECONDITION)


@pytest.mark.parametrize('change',[{'model':'different-model'},{'max_tokens':33},{'temperature':0.5},
    {'messages':[{'role':'user','content':[{'type':'text','text':'x','cache_control':{'type':'ephemeral'}}]}]}])
def test_request_must_match_frozen_model_parameter_and_billing_limits(change):
    ref,blobs,plan,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    plan=replace(plan,body=canonical_json({**json.loads(plan.body),**change}))
    with pytest.raises(StableError):
        profile.preflight(plan)


@pytest.mark.parametrize('usage,cost',[({'input_tokens':3,'output_tokens':2},18),({'input_tokens':0,'output_tokens':0},7),
    ({'input_tokens':None,'output_tokens':2},None),({},None)])
def test_root_reads_usage_from_original_wire_and_derives_price(usage,cost):
    ref,blobs,_,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    raw=json.dumps({'model':profile.model_id,'usage':usage}).encode()
    actual=profile.usage(raw)
    assert actual['cost_microunits']==cost
    assert actual['input_tokens']==usage.get('input_tokens')


@pytest.mark.parametrize('usage',[{'input_tokens':True,'output_tokens':0},{'output_tokens':-1},{'cost_microunits':0},
    {'cache_read_input_tokens':None},{'cache_creation_input_tokens':1},{'server_tool_use':{}},[]])
def test_unrecognized_or_uncertain_billable_dimensions_are_not_zeroed(usage):
    ref,blobs,_,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    with pytest.raises(StableError) as caught:
        profile.usage(canonical_json({'model':profile.model_id,'usage':usage}))
    assert caught.value.code==ErrorCode.INVALID_RESULT


def test_wire_duplicate_fields_wrong_model_and_excessive_depth_are_refused():
    ref,blobs,_,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    values=[b'{"model":"synthetic-model","usage":{"input_tokens":1,"input_tokens":0}}',
        canonical_json({'model':'different','usage':{'input_tokens':0,'output_tokens':0}}),
        b'{"model":"synthetic-model","unknown":'+b'['*40+b'0'+b']'*40+b'}']
    for raw in values:
        with pytest.raises(StableError) as caught:
            profile.usage(raw)
        assert caught.value.code==ErrorCode.INVALID_RESULT


@pytest.mark.parametrize('change',[{'tools':[{'type':'web_search_2026','name':'web_search'}]},
    {'messages':[{'role':'user','content':[{'type':'image','source':{'data':'synthetic'}}]}]},
    {'messages':[{'role':'assistant','content':[{'type':'thinking','thinking':'unsupported'}]}]},
    {'system':[{'type':'text','text':'x','cache_control':{'type':'ephemeral'}}]}])
def test_server_tools_images_and_reasoning_cannot_hide_unsupported_billing_in_known_parameters(change):
    ref,blobs,plan,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    with pytest.raises(StableError) as caught:
        profile.preflight(replace(plan,body=canonical_json({**json.loads(plan.body),**change})))
    assert caught.value.code==ErrorCode.FAILED_PRECONDITION


def test_basic_serial_function_tool_history_remains_supported_by_the_profile():
    ref,blobs,plan,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    body={**json.loads(plan.body),'tools':[{'name':'cap.echo','input_schema':{'type':'object'}}],
        'messages':[{'role':'assistant','content':[{'type':'tool_use','id':'call-1','name':'cap.echo','input':{'value':1}}]},
            {'role':'user','content':[{'type':'tool_result','tool_use_id':'call-1','content':'done','is_error':False}]}]}
    assert profile.preflight(replace(plan,body=canonical_json(body)))[0]>0


@pytest.mark.parametrize('name',['thinking','cache_control','server_tool'])
def test_protocol_words_in_business_schema_and_arguments_are_data(name):
    ref,blobs,plan,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    body={**json.loads(plan.body),
        'tools':[{'name':'cap.store','input_schema':{'type':'object','properties':{
            name:{'type':'object','properties':{'type':{'type':'string'}}}}}}],
        'messages':[
            {'role':'assistant','content':[{'type':'tool_use','id':'call-1','name':'cap.store',
                'input':{name:{'type':'ephemeral','value':'ordinary application data'}}}]},
            {'role':'user','content':[{'type':'tool_result','tool_use_id':'call-1','content':'stored'}]}]}
    tokens,output,cost=profile.preflight(replace(plan,body=canonical_json(body)))
    assert tokens==profile.count_input(canonical_json(body)) and output==8
    assert cost==profile.pricing.cost(tokens,8)


@pytest.mark.parametrize('name',['thinking','cache_control','server_tool'])
@pytest.mark.parametrize('position',['tool_definition','assistant_block','user_block'])
def test_protocol_extensions_at_structural_positions_remain_refused(name,position):
    ref,blobs,plan,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    definition={'name':'cap.store','input_schema':{'type':'object'}}
    assistant={'type':'tool_use','id':'call-1','name':'cap.store','input':{'value':1}}
    result={'type':'tool_result','tool_use_id':'call-1','content':'stored'}
    target={'tool_definition':definition,'assistant_block':assistant,'user_block':result}[position]
    target[name]={'type':'enabled'}
    body={**json.loads(plan.body),'tools':[definition],'messages':[
        {'role':'assistant','content':[assistant]},{'role':'user','content':[result]}]}
    with pytest.raises(StableError) as caught:
        profile.preflight(replace(plan,body=canonical_json(body)))
    assert caught.value.code==ErrorCode.FAILED_PRECONDITION


@pytest.mark.parametrize('change',[{'service_tier':'unknown-price'}, {'content':[{'type':'server_tool_use','name':'web_search'}]}])
def test_unknown_wire_billing_features_cannot_release_the_known_maximum_hold(change):
    ref,blobs,_,_=profile_case()
    profile,_=load_profile(ref,blobs.__getitem__)
    with pytest.raises(StableError) as caught:
        profile.usage(canonical_json({'model':profile.model_id,'usage':{'input_tokens':0,'output_tokens':0},**change}))
    assert caught.value.code==ErrorCode.INVALID_RESULT


def test_reader_integrity_errors_keep_their_code_without_leaking_diagnostics():
    ref,_,_,_=profile_case()
    def corrupt(_):
        raise StableError(code=ErrorCode.INTEGRITY_ERROR,message='synthetic private diagnostic')
    with pytest.raises(StableError) as caught:
        load_profile(ref,corrupt)
    assert caught.value.code==ErrorCode.INTEGRITY_ERROR
    assert 'private diagnostic' not in str(caught.value)
