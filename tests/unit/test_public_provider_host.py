"""Signed public Provider callbacks; absent enforcement fails before Invocation."""

import asyncio
import os

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex
from test_bound_harness import live_bundle, upload_install, wait_refs
from test_daemon_lifecycle import _authority


@pytest.mark.parametrize("backend", ["trusted_in_process", "in_memory"])
@pytest.mark.parametrize("provider", [True, "invalid", "async"])
def test_signed_public_provider_adapter_fails_before_invocation_when_profile_is_unavailable(tmp_path, backend, provider):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest, grants = live_bundle(controlled_provider=provider)
    async def run():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", execution_backend=backend,
            trusted_publishers=[sha256_hex(bundle.key.public_key().public_bytes_raw())])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest)
            report = await client.validate_harness_package(manifest)
            assert report["valid"], report["issues"]
            assert report["resolved_contract_versions"]["public_api"] == "1.15.0"
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id,
                harness_id=installed.resource["harness_id"], composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"],
                grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            before = daemon._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE use_kind='host_invocation'").fetchone()[0]
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json("public controlled Provider"), kind="task_input", media_type="application/json")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            terminal, done = await client.wait_task(task.task_id, timeout_s=10)
            expected = "FAILED_PRECONDITION" if provider is True else "INVALID_RESULT"
            assert done and terminal["status"] == "FAILED" and terminal["error"] == expected, terminal
            execution = await client.get_task_execution(task.task_id)
            assert execution["invocations"] == [] and execution["consumed_budget"].get("model_calls", 0) == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE use_kind='host_invocation'").fetchone()[0] == before
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE event_type IN ('provider_cost_reserved','provider_dispatch_authorized')").fetchone()[0] == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM execution_bindings").fetchone()[0] == 0
            assert terminal["result_artifact_id"] == ""
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(run())
