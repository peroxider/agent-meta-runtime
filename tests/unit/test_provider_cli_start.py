"""Native test launch is explicit, bounded and uses the installed CLI/IPC."""
import asyncio
import json
import os
import subprocess

import pytest

from agent_meta_runtime.sdk import connect
from test_daemon_process import command, run, wait_started
from test_provider_https import edge


@pytest.mark.parametrize('kind',['missing','directory','empty','oversized','invalid_pem'])
def test_bad_test_anchor_is_rejected_before_a_daemon_or_store_is_created(tmp_path,kind):
    path=tmp_path/'test-ca.pem'
    if kind=='directory':
        path.mkdir()
    elif kind!='missing':
        path.write_bytes(b'' if kind=='empty' else b'x'*65537 if kind=='oversized' else b'synthetic-invalid-public-CA')
    data=tmp_path/'never-created'
    result=run(data,'start','--controlled-provider-test-ca',str(path))
    assert result.returncode==2 and json.loads(result.stdout)['error']['code']=='INVALID_ARGUMENT'
    assert not data.exists() and b'synthetic-invalid-public-CA' not in result.stdout.encode()


def test_explicit_cli_test_launch_has_distinct_profile_and_dry_run_never_starts(tmp_path,edge):
    ca=tmp_path/'explicit-ca.pem'; ca.write_bytes(edge[6])
    data=tmp_path/'runtime'
    preview=run(data,'--dry-run','start','--controlled-provider-test-ca',str(ca))
    assert preview.returncode==0 and json.loads(preview.stdout)['result']['provider_execution']=='CONTROLLED_TEST_ONLY'
    assert not data.exists()
    assert run(data,'--dry-run','start','--execution-backend','in_memory','--controlled-provider-test-ca',str(ca)).returncode==2
    assert run(data,'init').returncode==0
    output,errors=tmp_path/'stdout.jsonl',tmp_path/'stderr.txt'
    with output.open('w') as out,errors.open('w') as err:
        process=subprocess.Popen(command(data,'start','--controlled-provider-test-ca',str(ca)),stdout=out,stderr=err,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            started=wait_started(process,output,errors)
            assert started['provider_execution']=='CONTROLLED_TEST_ONLY'
            async def inspect():
                client=await connect(data)
                try:
                    return await client.get_info()
                finally:
                    await client.aclose()
            info=asyncio.run(inspect())
            assert info.live and info.core_ready and not info.serving_ready
            assert run(data,'stop').returncode==0
            assert process.wait(timeout=10)==0
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=10)
