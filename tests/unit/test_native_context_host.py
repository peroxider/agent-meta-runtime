"""Real Host path with a Root-owned synthetic counter; not native GLM proof."""
import asyncio
import json
import os

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.context import glm53_context_tokenizer_descriptor
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority
from test_daemon_process import run


class SyntheticRootCounter:
    tokenizer_id=glm53_context_tokenizer_descriptor()['tokenizer_id']
    descriptor_content=canonical_json(glm53_context_tokenizer_descriptor())

    def count(self,content):
        return (len(content.decode('utf-8'))+1)//2


@pytest.mark.parametrize('mode',['available','missing','different_descriptor','forged_count'])
def test_missing_root_counter_fails_before_model_and_issued_projection_uses_its_counter(tmp_path,mode):
    run_init(tmp_path,insecure_dev_credential_file=os.name!='nt')
    bundle,manifest,grants=live_bundle(context_descriptor=glm53_context_tokenizer_descriptor(),
        root_projection=True,projection_echo=True,forge_native_count=mode=='forged_count')
    counter=SyntheticRootCounter() if mode!='missing' else None
    if mode=='different_descriptor': counter.descriptor_content=b'{}'
    publisher=sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority=_authority(tmp_path)
        daemon=RuntimeDaemon(tmp_path,allow_insecure_credentials=os.name!='nt',trusted_publishers=[publisher],context_tokenizer=counter)
        await daemon.start()
        client=await connect(tmp_path,authority=authority)
        try:
            installed=await upload_install(client,authority,bundle,manifest)
            await client.activate_harness(realm_id='realm://main',actor_id=authority.actor_id,harness_id=installed.resource['harness_id'],
                composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'],grant_requests=grants)
            await wait_refs(client,status='READY',serving=1)
            uploaded=await client.put_artifact(realm_id='realm://main',actor_id=authority.actor_id,kind='task_input',
                media_type='application/json',content=canonical_json('你好，世界'))
            task=await client.submit_task(realm_id='realm://main',actor_id=authority.actor_id,input_artifact_id=uploaded['artifact_id'])
            result,done=await client.wait_task(task.task_id,timeout_s=5)
            assert done
            execution=await client.get_task_execution(task.task_id)
            if mode=='available':
                assert len(execution['invocations'])==1 and execution['invocations'][0]['kind']=='MODEL'
                assert result['status']=='SUCCEEDED',result
                rows=list(daemon._conn.execute('SELECT manifest_json,rendered_artifact_id FROM context_projections WHERE task_id=?',(task.task_id,)))
                assert len(rows)==1
                value=json.loads(rows[0][0])
                body=daemon._catalog.read_artifact(rows[0][1])
                assert value['tokenizer_id']==counter.tokenizer_id
                assert value['total_tokens']==counter.count(body)!=len(body)
            else:
                assert execution['invocations']==[]
                assert result['error']==('INVALID_RESULT' if mode=='forged_count' else 'FAILED_PRECONDITION'),result
                assert daemon._conn.execute('SELECT COUNT(*) FROM context_projections WHERE task_id=?',(task.task_id,)).fetchone()[0]==(1 if mode=='forged_count' else 0)
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


@pytest.mark.parametrize('mode',['missing','directory','invalid'])
def test_native_cli_input_failure_does_not_create_a_runtime(tmp_path,mode):
    path=tmp_path/'tokenizer.json'
    if mode=='directory': path.mkdir()
    elif mode=='invalid': path.write_bytes(b'UNVERIFIED_TOKENIZER_DATA_CANARY')
    data=tmp_path/'not-created'
    result=run(data,'start','--context-tokenizer-json',str(path))
    assert result.returncode!=0
    assert json.loads(result.stdout)['error']['code']==('INTEGRITY_ERROR' if mode=='invalid' else 'INVALID_ARGUMENT')
    assert not data.exists()
    assert 'UNVERIFIED_TOKENIZER_DATA_CANARY' not in result.stdout
