"""Strict State payloads and local CLI preparation; no server-side effects."""
import asyncio
import json

import pytest
from agent_meta_runtime.domain.state_contract import state_payload
from agent_meta_runtime.sdk import AgentMetaClient, StableError, decode_command
from agent_meta_runtime.interfaces.cli import build_parser
from agent_meta_runtime.interfaces.cli.main import cmd_state

STATE='state://01900000-0000-7000-8000-000000000000'
REV='state-revision://01900000-0000-7000-8000-000000000001'
REF='artifact://sha256/'+'a'*64
BASE={'state_id':STATE,'owner_id':'capability://seed.state','schema_id':REF,'content_artifact_id':REF}


@pytest.mark.parametrize('extra',[
    {'state_id':None},{'state_id':'task://01900000-0000-7000-8000-000000000000'},
    {'owner_id':'principal://operator-root/01900000-0000-7000-8000-000000000000'},
    {'schema_id':'schema://unpublished'},{'content_artifact_id':'file://local'},
    {'purpose':[]},{'purpose':'UNRECOGNIZED'},{'controller_principal_id':'forged'},
    {'force':True},{'redaction_policy_artifact_id':None},
])
def test_state_create_rejects_unknown_fields_and_invalid_refs(extra):
    with pytest.raises(StableError) as failed:
        state_payload('state.create/v1',{**BASE,**extra})
    assert failed.value.code=='INVALID_ARGUMENT'


@pytest.mark.parametrize('cas',[None,True,False,0,-1,1.0,'1',2**53])
def test_state_write_requires_a_strict_positive_cas(cas):
    with pytest.raises(StableError):
        state_payload('state.write/v1',{'state_id':STATE,'schema_id':REF,'content_artifact_id':REF,
            'expected_state_revision_id':REV,'expected_cas_revision':cas})


def test_state_envelope_builders_are_locally_validated_and_replayable():
    client=AgentMetaClient(None)
    value=client.build_state_create(realm_id='realm://main',actor_id='principal://operator-root/01900000-0000-7000-8000-000000000000',
        owner_id='capability://seed.state',schema_id=REF,content_artifact_id=REF,state_id=STATE)
    command=decode_command(value)
    assert command.payload['state_id']==STATE and command.expected_meta_revision is None
    assert command.payload_type=='state.create/v1'


@pytest.mark.parametrize('operation',[
    ['create','--state-id',STATE,'--owner-id','capability://seed.state','--schema-id',REF,'--content-artifact',REF],
    ['get',STATE],
    ['write',STATE,'--expected-revision',REV,'--expected-cas','1','--schema-id',REF,'--content-artifact',REF],
])
def test_state_cli_dry_run_constructs_an_envelope_without_transport(capsys,operation,tmp_path):
    args=build_parser().parse_args(['--data-dir',str(tmp_path),'--output','json','--dry-run','--actor',
        'principal://operator-root/01900000-0000-7000-8000-000000000000','state',*operation])
    assert asyncio.run(cmd_state(AgentMetaClient(None),args))==0
    result=json.loads(capsys.readouterr().out)
    value=result['result']
    assert value['dry_run'] and value['would_change']
    command=decode_command(value['command_envelope_jcs'])
    assert command.payload['state_id']==STATE
