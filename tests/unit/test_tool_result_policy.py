"""Ordinary callback tool boundaries, including durable fatal-error replay."""
import asyncio
from dataclasses import replace
import json
import os

import pytest

from agent_meta_runtime.application.task_host import TaskSession
from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import StableError, connect
from agent_meta_runtime.sdk.packages import canonical_json, decode_package, encode_package, build_manifest, sha256_hex
from test_bound_harness import upload_install, wait_refs
from test_daemon_lifecycle import _authority
from test_resource_host import resource_bundle, submit

CANARY = 'PURE_TOOL_SECRET_CANARY_5b102'


def pure_bundle(behavior='normal'):
    bundle, _, grants = resource_bundle('artifact.put/v1')
    _, files = decode_package(bundle.blobs[bundle.manifest['package_artifact_id']])
    code = files['probe.py'].decode().replace(
        'return HarnessAdapter(run_task,model,{},probe,resource_tools=resources)',
        'return HarnessAdapter(run_task,model,{NAME:tool},probe)')
    body = {
        'normal': "assert json.loads(request.call.arguments_json)['api_key']=='[REDACTED]'; return InvocationResult(content=canonical_json({'api_key':CANARY,'public':42}))",
        'schema': "return InvocationResult(content=b'[]')",
        'duplicate': "return InvocationResult(content=b'{\"v\":1,\"v\":2}')",
        'nan': "return InvocationResult(content=b'{\"v\":NaN}')",
        'utf8': "return InvocationResult(content=bytes([255]))",
        'size': "return InvocationResult(content=canonical_json({'v':'x'*(1024*1024)}))",
        'expansion': "return InvocationResult(content=canonical_json({'v':' '.join(['Bearer a']*100000)}))",
        'after_schema': "return InvocationResult(content=canonical_json({'api_key':CANARY}))",
        'error': "return InvocationResult(error_code='FEATURE_UNAVAILABLE')",
        'wait': "await asyncio.Event().wait()",
    }[behavior]
    code += f"\nimport asyncio\nCANARY={CANARY!r}\nCALLS=0\nasync def tool(request):\n    global CALLS\n    CALLS+=1\n    assert CALLS==1, 'confirmed callback rerun'\n    {body}\n"
    raw = code.encode()
    provenance = bundle.doc({'schema': 'fixture-provenance/v1', 'source_files': {'probe.py': sha256_hex(raw)}})
    bundle.meta = replace(bundle.meta, build_provenance_artifact_id=provenance)
    package = bundle.add(encode_package(build_manifest(bundle.meta, {'probe.py': raw}), {'probe.py': raw}))
    descriptors = []
    for reference in bundle.manifest['capability_descriptor_artifact_ids']:
        descriptor = json.loads(bundle.blobs[reference])
        descriptor['artifact_id'] = package
        for operation in descriptor['operations']:
            if 'resource_contract' in operation:
                del operation['resource_contract']
                operation.update(idempotency='PURE', effects=['none'], required_permissions=[])
                if behavior == 'after_schema':
                    operation['output_schema_artifact_id'] = bundle.doc({'type':'object', 'required':['api_key'],
                        'properties':{'api_key':{'const':CANARY}}, 'additionalProperties':False})
        descriptors.append(bundle.doc(descriptor))
    composition = json.loads(bundle.blobs[bundle.manifest['composition_template_artifact_id']])
    for slot in composition['slots'].values():
        slot['artifact_id'] = package
    policy = json.loads(bundle.blobs[bundle.manifest['loop_policy_artifact_id']])
    policy['stop_on_tool_error'] = False
    bundle.manifest.update(package_artifact_id=package, build_provenance_artifact_id=provenance,
        capability_descriptor_artifact_ids=sorted(descriptors), composition_template_artifact_id=bundle.doc(composition),
        loop_policy_artifact_id=bundle.doc(policy))
    return bundle, bundle.sign(), grants


async def environment(root, behavior, backend):
    bundle, manifest, grants = pure_bundle(behavior)
    authority = _authority(root)
    daemon = RuntimeDaemon(root, allow_insecure_credentials=os.name != 'nt', execution_backend=backend,
        trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
    await daemon.start()
    client = await connect(root, authority=authority)
    installation = await upload_install(client, authority, bundle, manifest)
    await client.activate_harness(realm_id='realm://main', actor_id=authority.actor_id,
        harness_id=installation.resource['harness_id'], composition_body_artifact_id=bundle.manifest['composition_template_artifact_id'], grant_requests=grants)
    await wait_refs(client, status='READY', serving=1)
    return daemon, client, authority


@pytest.mark.parametrize('backend', ['trusted_in_process', 'in_memory'])
def test_ordinary_tool_redacts_request_and_result_before_publication(tmp_path, backend):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, 'normal', backend)
        try:
            _, terminal, execution = await submit(client, authority, {'api_key': CANARY})
            assert terminal['status'] == 'SUCCEEDED', terminal
            tool = next(row for row in execution['invocations'] if row['kind'] == 'CAPABILITY')
            request = await client.get_artifact_content(tool['input_artifact_id'])
            output = await client.get_artifact_content(tool['output_artifact_id'])
            assert CANARY.encode() not in request and CANARY.encode() not in output
            assert json.loads(output) == {'api_key':'[REDACTED]', 'public':42}
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('backend', ['trusted_in_process', 'in_memory'])
@pytest.mark.parametrize('behavior', ['schema','duplicate','nan','utf8','size','expansion','after_schema'])
def test_invalid_tool_output_is_fatal_and_never_published(tmp_path, backend, behavior):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    async def run():
        daemon, client, authority = await environment(tmp_path, behavior, backend)
        try:
            _, terminal, execution = await submit(client, authority, {})
            assert terminal['error'] == 'INVALID_RESULT', terminal
            tool = next(row for row in execution['invocations'] if row['kind'] == 'CAPABILITY')
            assert tool['status'] == 'FAILED' and tool['output_artifact_id'] is None
            assert len(execution['invocations']) == 2
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())


@pytest.mark.parametrize('backend', ['trusted_in_process', 'in_memory'])
@pytest.mark.parametrize('behavior', ['schema', 'error'])
def test_replay_keeps_exception_distinct_from_allowed_tool_error(tmp_path, monkeypatch, backend, behavior):
    run_init(tmp_path, insecure_dev_credential_file=os.name != 'nt')
    original = TaskSession.invoke_tool
    async def replay(session, call):
        if behavior == 'schema':
            with pytest.raises(StableError) as first:
                await original(session, call)
            session._ordinal -= 1
            with pytest.raises(StableError) as second:
                await original(session, call)
            assert first.value.code == second.value.code == 'INVALID_RESULT'
            raise first.value
        first = await original(session, call)
        session._ordinal -= 1
        session._pending.insert(0, call)
        second = await original(session, call)
        assert first == second and first.error_code == 'FEATURE_UNAVAILABLE'
        return first
    monkeypatch.setattr(TaskSession, 'invoke_tool', replay)
    async def run():
        daemon, client, authority = await environment(tmp_path, behavior, backend)
        try:
            _, terminal, execution = await submit(client, authority, {})
            assert terminal['status'] == ('FAILED' if behavior == 'schema' else 'SUCCEEDED'), terminal
            assert execution['consumed_budget']['steps'] == (2 if behavior == 'schema' else 3)
            assert len([row for row in execution['invocations'] if row['kind'] == 'CAPABILITY']) == 1
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())
