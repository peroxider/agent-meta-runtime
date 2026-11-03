"""Real daemon + signed AMPAK + instance/health cutover over public IPC.

Runtime-owned integration fixture; Task execution gates are exercised separately.
"""

import asyncio
from dataclasses import replace
import json
import os
import time

import pytest

from agent_meta_runtime.interfaces.cli.init import run_init
from agent_meta_runtime.interfaces.daemon import RuntimeDaemon
from agent_meta_runtime.sdk import connect
from agent_meta_runtime.sdk.packages import canonical_json, sha256_hex, encode_package, build_manifest
from agent_meta_runtime.sdk.context import build_context_artifacts
from test_daemon_lifecycle import _authority
from test_public_package_contract import Bundle


def live_bundle(health="READY", *, model_max_uses=None, version="0.1.0", descriptor_revision=1, controlled_provider=False, provider_declaration=None, provider_normalizer='default'):
    bundle = Bundle()
    provider_profile = bundle.doc({"schema": "fixture-unavailable-provider-profile/v1"}) if controlled_provider else None
    if provider_declaration is not None:
        provider_profile,profile_blobs=provider_declaration
        bundle.blobs.update(profile_blobs)
    provider_body = canonical_json({"model": "synthetic-model", "messages": [{"role": "user", "content": "synthetic"}], "max_tokens": 1, "stream": False})
    prepare_expression = "{}" if controlled_provider == "invalid" else f"ProviderRequestPlan({provider_profile!r}, {provider_body!r})"
    prepare_callback = "prepare_provider_async" if controlled_provider == "async" else "prepare_provider"
    normalized_value = "{}" if provider_normalizer == 'invalid' else "ModelResponse((TextPart('controlled synthetic response'),), 'STOP', ProviderUsage(0, 0, 0))" if provider_normalizer == 'zero_claim' else "ModelResponse((TextPart('controlled synthetic response'),), 'STOP', ProviderUsage(None, None, None))"
    code = f"""
import json
import asyncio
import uuid
from agent_meta_runtime.sdk.host import (HarnessAdapter, HealthStatus, ModelResponse, TextPart, JsonPart,
    ProviderUsage, ProjectionInput, RenderedSection, SourceRef, terminal_result)
from agent_meta_runtime.sdk.host import ProviderAdapter, ProviderRequestPlan
from agent_meta_runtime.sdk.context import build_projection_input
async def run_task(task, host):
    assert not any(hasattr(host, name) for name in ('_store', '_bound', 'conn', 'authority', '__dict__'))
    manifest = json.loads(task.harness_manifest_content)
    view = json.loads(task.acceptance_view_content)
    assert view['composition'] == json.loads(task.composition_content)
    assert view['meta_revision'] == task.accepted_meta_revision
    assert len(view['backend_profile_hash']) == 64
    projection = await host.project_context(build_projection_input(task))
    if json.loads(task.input_content) == 'actual Task input':
        for _ in range(99):
            replayed = await host.project_context(build_projection_input(task))
            assert replayed is projection
    response = await host.invoke_model(projection)
    if json.loads(task.input_content) == 'replay-confirmed':
        await asyncio.sleep(.5)
    return terminal_result(response)
async def model(request):
    assert request.history_content == b'[]'
    if json.loads(request.task.input_content) == 'pending':
        await asyncio.Event().wait()
    if json.loads(request.task.input_content) == 'replay-confirmed':
        return ModelResponse((JsonPart({{'nonce': uuid.uuid4().hex}}),), 'STOP', ProviderUsage(None, None, 0))
    return ModelResponse((TextPart('fixture model'), JsonPart({{'answer': 42}}), TextPart('tail')), 'STOP', ProviderUsage(None, None, 0))
async def probe(request):
    return HealthStatus({health!r}, 'SELF_TEST')
def prepare_provider(request):
    return {prepare_expression}

async def prepare_provider_async(request):
    return prepare_provider(request)

def normalize_provider(response):
    return {normalized_value}

def create():
    return HarnessAdapter(run_task, {'None' if controlled_provider else 'model'}, {{}}, probe,
        provider={f'ProviderAdapter({prepare_callback}, normalize_provider)' if controlled_provider else 'None'})
""".encode()
    files = {"probe.py": code}
    context_profile, context_artifacts = build_context_artifacts(input_schema={"type": "string"}, selected_operation_ids=[], provider_id="fixture")
    bundle.blobs.update(context_artifacts)
    provenance = bundle.doc({"schema": "fixture-provenance/v1", "source_files": {"probe.py": sha256_hex(code)}})
    metadata = replace(bundle.meta, version=version, entrypoint="probe:create", build_provenance_artifact_id=provenance,
        runtime_constraints={"context_profile_artifact_id": context_profile,
            **({"provider_profile_artifact_id":provider_profile} if provider_declaration is not None else {})})
    bundle.meta = metadata
    package = bundle.add(encode_package(build_manifest(metadata, files), files))
    schema = bundle.doc({"type": "object"})
    operations = []
    for operation, effects, permissions in (("probe.model", ["none"], []), ("example.model", ["model.invoke"], ["model.invoke"])):
        operations.append({"operation_id": operation, "input_schema_artifact_id": schema,
            "output_schema_artifact_id": schema, "effects": effects, "required_permissions": permissions,
            "idempotency": "PURE" if not permissions else "NONE", "retry_semantics": "NEVER"})
    descriptor = {"capability_id": "capability://example.model", "descriptor_revision": descriptor_revision,
        "artifact_id": package, "placement": "in_process", "trust_class": "builtin_or_signed",
        "operations": operations, "provides": [], "requires": []}
    if provider_declaration is not None:
        descriptor['runtime_constraints']={'provider_profile_artifact_id':provider_profile}
    grants = [{"permission": "model.invoke", "scope": {"realm_id": "realm://main",
        "targets": [{"type": "CAPABILITY", "id": descriptor["capability_id"]}]}}]
    if model_max_uses is not None:
        grants[0]["max_uses"] = model_max_uses
    bundle.manifest.update({"package_version": version, "package_artifact_id": package, "build_provenance_artifact_id": provenance,
        "capability_descriptor_artifact_ids": [bundle.doc(descriptor)],
        "composition_template_artifact_id": bundle.doc({"schema": "composition/v1", "realm_id": "realm://main", "wiring": [],
            "slots": {"model": {"capability_id": descriptor["capability_id"], "descriptor_revision": descriptor_revision, "artifact_id": package,
                "placement": "in_process", "criticality": "REQUIRED", "degradation_policy": "REJECT_TASK", "health_probe": {"operation_id": "probe.model"}}}}),
        "grant_requests_artifact_id": bundle.doc({"schema": "harness-grant-requests/v1", "requests": grants})})
    manifest_id = bundle.sign()
    return bundle, manifest_id, grants


async def upload_install(client, authority, bundle, manifest_id):
    for raw in list(bundle.blobs.values()):
        await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id, content=raw, kind="code", media_type="application/octet-stream")
    report = await client.validate_harness_package(manifest_id)
    assert report["valid"], report["issues"]
    return await client.install_harness(realm_id="realm://main", actor_id=authority.actor_id,
        package_name=bundle.meta.name, package_version=bundle.meta.version,
        manifest_artifact_id=manifest_id, package_artifact_id=bundle.manifest["package_artifact_id"])


async def wait_refs(client, *, status, serving):
    deadline = asyncio.get_running_loop().time() + 5
    while asyncio.get_running_loop().time() < deadline:
        refs = await client.get_refs()
        if refs["reconcile_status"] == status and refs["serving_revision"] == serving:
            return refs
        await asyncio.sleep(.02)
    raise AssertionError(f"reconcile did not reach expected state: {refs}")


def test_signed_package_loads_probes_cuts_over_and_rebinds_after_restart(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle()
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            harness_id = installed.resource["harness_id"]
            activated = await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=harness_id,
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            assert (await client.get_harness(harness_id))["status"] == "ACTIVE"
            assert daemon._catalog.healthy_for(activated.resource["composition_id"])
            instance = daemon._conn.execute("SELECT instance_id,status,binding_incarnation FROM capability_instances").fetchone()
            assert instance[0].startswith("instance://") and instance[1:] == ("ACTIVE", 1)
            assert (await client.get_info()).serving_ready
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json('actual Task input'), kind="task_input", media_type="text/plain")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id,
                input_artifact_id=uploaded["artifact_id"])
            # 100 durable projections now share scheduling with management I/O.
            # This observation timeout is separate from a Task deadline.
            terminal, done = await client.wait_task(task.task_id, timeout_s=15)
            assert done and terminal["status"] == "SUCCEEDED", terminal
            from agent_meta_runtime.sdk.host import TerminalResult, TextPart, JsonPart, encode_terminal_result
            expected = encode_terminal_result(TerminalResult((TextPart('fixture model'), JsonPart({'answer': 42}), TextPart('tail'))))
            assert terminal["result_artifact_id"] == "artifact://sha256/" + sha256_hex(expected)
            invocation = daemon._conn.execute("SELECT status,usage_json FROM invocations").fetchone()
            assert invocation[0] == "SUCCEEDED" and json.loads(invocation[1]) == {"input_tokens": None, "output_tokens": None, "cost_microunits": 0}
            assert daemon._conn.execute("SELECT COUNT(*) FROM context_projections").fetchone()[0] == 1
            projection_raw, rendered_id = daemon._conn.execute("SELECT manifest_json,rendered_artifact_id FROM context_projections").fetchone()
            projection = json.loads(projection_raw)
            from agent_meta_runtime.sdk.context import SECTION_IDS
            assert [section["section_id"] for section in projection["sections"]] == list(SECTION_IDS)
            assert len({section["renderer"] for section in projection["sections"]}) == 5
            assert projection["total_tokens"] == len(daemon._catalog.read_artifact(rendered_id))
            assert projection["total_tokens"] <= projection["budget_tokens"]
            assert any(source["kind"] == "constitution" for source in projection["source_refs"])
            assert any(source["kind"] == "runtime" for source in projection["source_refs"])
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE entity_type='artifact' AND event_type='artifact_registered' AND json_extract(CAST(payload_json AS TEXT),'$.projection_id')=?", (projection["projection_id"],)).fetchone()[0] == 1
            consumed = json.loads(daemon._conn.execute("SELECT consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()[0])
            assert consumed == {"turns": 1, "model_calls": 1, "steps": 1, "effects": 1, "cost_microunits": 0}
            before_changes = daemon._conn.total_changes
            execution = await client.get_task_execution(task.task_id)
            assert daemon._conn.total_changes == before_changes
            assert execution["status"] == "SUCCEEDED" and execution["resource_type"] == "task-execution/v1"
            assert execution["accepted_meta_revision"] > 0 and execution["consumed_budget"] == consumed
            assert execution["input_artifact_id"] == uploaded["artifact_id"]
            assert execution["acceptance_view_artifact_id"].startswith("artifact://sha256/")
            assert len(execution["invocations"]) == len(execution["projections"]) == 1
            assert execution["invocations"][0]["status"] == "SUCCEEDED"
            assert execution["invocations"][0]["usage"]["input_tokens"] is None
            assert execution["projections"][0]["manifest"] == projection
            assert "backend_ref" not in execution["invocations"][0]
        finally:
            await client.aclose()
            await daemon.close()
        restarted = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await restarted.start()
        client = await connect(tmp_path, authority=authority)
        try:
            await wait_refs(client, status="READY", serving=1)
            rebound = restarted._conn.execute("SELECT instance_id,status,binding_incarnation FROM capability_instances").fetchone()
            assert rebound[0] == instance[0] and rebound[1:] == ("ACTIVE", 2)
            await client.deactivate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=harness_id)
            await wait_refs(client, status="READY", serving=0)
            assert (await client.get_harness(harness_id))["status"] == "INACTIVE"
            assert restarted._conn.execute("SELECT status FROM capability_instances").fetchone()[0] == "RELEASED"
            await client.uninstall_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=harness_id)
            assert (await client.get_harness(harness_id))["status"] == "UNINSTALLED"
        finally:
            await client.aclose()
            await restarted.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("tamper", ["content", "count", "policy", "renderer", "source", "budget"])
def test_host_recomputes_context_before_accepting_package_projection(tmp_path, monkeypatch, tamper):
    from agent_meta_runtime.adapters.store.host_execution import HostExecutionStore
    original = HostExecutionStore.save_projection
    def forged(self, task, request):
        if tamper in {"content", "count", "renderer"}:
            section = request.sections[1]
            changes = {"content": {"content": b'"raw secret"', "token_count": 12},
                "count": {"token_count": section.token_count + 1},
                "renderer": {"renderer_artifact_id": request.policy_artifact_id}}[tamper]
            request = replace(request, sections=(request.sections[0], replace(section, **changes), *request.sections[2:]))
        elif tamper == "policy":
            request = replace(request, policy_artifact_id=request.redaction_policy_artifact_id)
        elif tamper == "source":
            request = replace(request, source_refs=request.source_refs[1:])
        else:
            request = replace(request, budget_tokens=request.budget_tokens + 1)
        return original(self, task, request)
    monkeypatch.setattr(HostExecutionStore, "save_projection", forged)
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle()
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json("Bearer abcdefghijklmnop"), kind="task_input", media_type="application/json")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            terminal, done = await client.wait_task(task.task_id, timeout_s=3)
            assert done and terminal["status"] == "FAILED" and terminal["error"] == "INVALID_RESULT", terminal
            assert daemon._conn.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 0
            assert daemon._conn.execute("SELECT COUNT(*) FROM context_projections").fetchone()[0] == 0
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("case,expected,error", [
    ("budget", "FAILED", "RESOURCE_EXHAUSTED"),
    ("exhausted_service_grant", "FAILED", "AUTHORITY_DENIED"),
    ("cancel", "CANCELLED", "EXTERNAL_EFFECT_UNKNOWN"),
    ("deadline", "TIMED_OUT", "EXTERNAL_EFFECT_UNKNOWN"),
    ("expired_in_queue", "TIMED_OUT", "DEADLINE_EXCEEDED"),
])
def test_actual_task_budget_authority_cancel_and_deadline(tmp_path, case, expected, error):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle(model_max_uses=1 if case == "exhausted_service_grant" else None)
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json('pending' if case in ("cancel", "deadline") else 'input'), kind="task_input", media_type="text/plain")
            if case == "exhausted_service_grant":
                first = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
                result, terminal = await client.wait_task(first.task_id, timeout_s=3)
                assert terminal and result["status"] == "SUCCEEDED", result
            # This case proves expiry after dispatch. A 200 ms window can
            # expire during IPC/admission under load and exercises the separate
            # expired-in-queue case instead. Require the causal precondition.
            deadline = time.time_ns() // 1000 + 5_000_000 if case == "deadline" else time.time_ns() // 1000 - 1 if case == "expired_in_queue" else None
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"],
                budget={"max_steps": 0} if case == "budget" else None, deadline_at_us=deadline)
            if case in ("cancel", "deadline"):
                end = asyncio.get_running_loop().time() + 3
                while not daemon._conn.execute("SELECT 1 FROM invocations WHERE action_id=? AND status='RUNNING'", (task.root_action_id,)).fetchone():
                    assert asyncio.get_running_loop().time() < end
                    await asyncio.sleep(.005)
            if case == "deadline":
                assert time.time_ns() // 1000 < deadline, 'dispatch was not observed before the deadline'
            if case == "cancel":
                await client.cancel_task(realm_id="realm://main", actor_id=authority.actor_id, task_id=task.task_id)
            terminal, done = await client.wait_task(task.task_id, timeout_s=8 if case == "deadline" else 3)
            assert done and terminal["status"] == expected and terminal["error"] == error, terminal
            rows = daemon._conn.execute("SELECT status,error_json FROM invocations WHERE action_id=?", (task.root_action_id,)).fetchall()
            if case in ("cancel", "deadline"):
                assert len(rows) == 1 and rows[0][0] == "FAILED" and json.loads(rows[0][1]) == "EXTERNAL_EFFECT_UNKNOWN"
                consumed = json.loads(daemon._conn.execute("SELECT consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()[0])
                assert consumed["model_calls"] == consumed["turns"] == consumed["steps"] == 1
                assert consumed["cost_microunits"] is None
            else:
                assert rows == []  # denial precedes dispatch and debit
                assert json.loads(daemon._conn.execute("SELECT consumed_budget_json FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()[0]) == {}
            assert daemon._conn.execute("SELECT COUNT(*) FROM facts WHERE entity_id=? AND event_type IN ('task_failed','task_cancelled','task_timed_out')", (task.task_id,)).fetchone()[0] == 1
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


@pytest.mark.parametrize("confirmed", [False, True])
@pytest.mark.parametrize("wrong_profile", [False, True])
def test_restart_never_reissues_unknown_or_confirmed_provider_call(tmp_path, confirmed, wrong_profile):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle()
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json('replay-confirmed' if confirmed else 'pending'), kind="task_input", media_type="text/plain")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            end = asyncio.get_running_loop().time() + 2
            target = "SUCCEEDED" if confirmed else "RUNNING"
            while True:
                invocation = daemon._conn.execute("SELECT invocation_id,status,output_artifact_id FROM invocations").fetchone()
                if invocation and invocation[1] == target:
                    break
                assert asyncio.get_running_loop().time() < end
                await asyncio.sleep(.002)
            if confirmed:
                from agent_meta_runtime.sdk.host import decode_model_response, encode_terminal_result, terminal_result
                original = daemon._catalog.read_artifact(invocation[2])
                expected_id = "artifact://sha256/" + sha256_hex(encode_terminal_result(terminal_result(decode_model_response(original))))
            assert (await client.get_task(task.task_id))["status"] == "RUNNING"
        finally:
            await client.aclose()
            await daemon.close()
        restarted = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await restarted.start()
        if wrong_profile:
            # Runtime-owned fault injection of an unavailable historical
            # profile; external consumer tests never alter Host state.
            restarted._task_host.store.profile_hash = "0" * 64
        client = await connect(tmp_path, authority=authority)
        try:
            terminal, done = await client.wait_task(task.task_id, timeout_s=4)
            succeeds = confirmed and not wrong_profile
            assert done and terminal["status"] == ("SUCCEEDED" if succeeds else "FAILED_RECOVERY"), terminal
            assert terminal["result_artifact_id"] == (expected_id if succeeds else "")
            if confirmed and wrong_profile:
                assert terminal["error"] == "CONTRACT_INCOMPATIBLE"
            rows = restarted._conn.execute("SELECT invocation_id,status FROM invocations").fetchall()
            assert rows == [(invocation[0], "SUCCEEDED" if confirmed else "FAILED")]
            consumed = json.loads(restarted._conn.execute("SELECT consumed_budget_json FROM tasks").fetchone()[0])
            assert consumed["model_calls"] == consumed["turns"] == consumed["steps"] == 1
            assert restarted._conn.execute("SELECT COUNT(*) FROM context_projections").fetchone()[0] == 1
        finally:
            await client.aclose()
            await restarted.close()
    asyncio.run(scenario())


def test_unhealthy_real_probe_does_not_publish_serving(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle("UNHEALTHY")
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="FAILED", serving=0)
            assert (await client.get_harness(installed.resource["harness_id"]))["status"] == "INSTALLED"
            assert daemon._conn.execute("SELECT status FROM capability_instances").fetchone()[0] == "FAILED"
            assert daemon._conn.execute("SELECT status FROM authority_grants WHERE parent_grant_id IS NOT NULL").fetchone()[0] == "REVOKED"
        finally:
            await client.aclose()
            await daemon.close()
    asyncio.run(scenario())


def test_failed_upgrade_keeps_old_serving_authority_and_recovers_it_after_restart(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    good, good_manifest, good_grants = live_bundle()
    bad, bad_manifest, bad_grants = live_bundle("UNHEALTHY", version="0.2.0", descriptor_revision=2)
    publishers = [sha256_hex(bundle.key.public_key().public_bytes_raw()) for bundle in (good, bad)]
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=publishers)
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, good, good_manifest)
            active = await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=good.manifest["composition_template_artifact_id"], grant_requests=good_grants)
            await wait_refs(client, status="READY", serving=1)
            old_instance = daemon._conn.execute("SELECT instance_id,binding_incarnation FROM capability_instances").fetchone()
            failed = await upload_install(client, authority, bad, bad_manifest)
            candidate = await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=failed.resource["harness_id"],
                composition_body_artifact_id=bad.manifest["composition_template_artifact_id"], grant_requests=bad_grants)
            refs = await wait_refs(client, status="FAILED", serving=1)
            assert refs["desired_revision"] == 2 and refs["realized_revision"] == 1
            assert (await client.get_info()).serving_ready
            assert (await client.get_view())["serving_ready"]
            assert (await client.get_harness(installed.resource["harness_id"]))["status"] == "ACTIVE"
            assert (await client.get_harness(failed.resource["harness_id"]))["status"] == "INSTALLED"
            def statuses(composition_id):
                raw = daemon._conn.execute("SELECT payload_json FROM facts WHERE event_type='harness_activated' AND json_extract(CAST(payload_json AS TEXT),'$.phase')='requested' AND json_extract(CAST(payload_json AS TEXT),'$.composition_id')=?", (composition_id,)).fetchone()[0]
                return [daemon._conn.execute("SELECT status FROM authority_grants WHERE grant_id=?", (grant_id,)).fetchone()[0] for grant_id in json.loads(raw)["grant_ids"]]
            assert statuses(active.resource["composition_id"]) == ["ACTIVE"]
            assert statuses(candidate.resource["composition_id"]) == ["REVOKED"]
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id,
                content=canonical_json('old serving still works'), kind="task_input", media_type="text/plain")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            result, terminal = await client.wait_task(task.task_id, timeout_s=3)
            assert terminal and result["status"] == "SUCCEEDED", result
            assert task.serving_revision == 1
        finally:
            await client.aclose()
            await daemon.close()
        restarted = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=publishers)
        await restarted.start()
        client = await connect(tmp_path, authority=authority)
        try:
            end = asyncio.get_running_loop().time() + 5
            while not (await client.get_info()).serving_ready:
                assert asyncio.get_running_loop().time() < end
                await asyncio.sleep(.01)
            refs = await client.get_refs()
            assert refs["desired_revision"] == 2 and refs["serving_revision"] == 1 and refs["reconcile_status"] == "FAILED"
            instance = restarted._conn.execute("SELECT instance_id,binding_incarnation FROM capability_instances WHERE composition_id=?", (active.resource["composition_id"],)).fetchone()
            assert instance == (old_instance[0], old_instance[1] + 1)
            assert not restarted._catalog.healthy_for(candidate.resource["composition_id"])
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            result, terminal = await client.wait_task(task.task_id, timeout_s=3)
            assert terminal and result["status"] == "SUCCEEDED" and task.serving_revision == 1, result
        finally:
            await client.aclose()
            await restarted.close()
    asyncio.run(scenario())


def test_removed_publisher_trust_blocks_restart_execution_and_closes_frozen_task(tmp_path):
    run_init(tmp_path, insecure_dev_credential_file=os.name != "nt")
    bundle, manifest_id, grants = live_bundle()
    publisher = sha256_hex(bundle.key.public_key().public_bytes_raw())
    async def scenario():
        authority = _authority(tmp_path)
        daemon = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt", trusted_publishers=[publisher])
        await daemon.start()
        client = await connect(tmp_path, authority=authority)
        try:
            installed = await upload_install(client, authority, bundle, manifest_id)
            await client.activate_harness(realm_id="realm://main", actor_id=authority.actor_id, harness_id=installed.resource["harness_id"],
                composition_body_artifact_id=bundle.manifest["composition_template_artifact_id"], grant_requests=grants)
            await wait_refs(client, status="READY", serving=1)
            uploaded = await client.put_artifact(realm_id="realm://main", actor_id=authority.actor_id, content=canonical_json('replay-confirmed'), kind="task_input", media_type="text/plain")
            task = await client.submit_task(realm_id="realm://main", actor_id=authority.actor_id, input_artifact_id=uploaded["artifact_id"])
            end = asyncio.get_running_loop().time() + 3
            while not daemon._conn.execute("SELECT 1 FROM invocations WHERE status='SUCCEEDED'").fetchone():
                assert asyncio.get_running_loop().time() < end
                await asyncio.sleep(.002)
            assert (await client.get_task(task.task_id))["status"] == "RUNNING"
        finally:
            await client.aclose()
            await daemon.close()
        restarted = RuntimeDaemon(tmp_path, allow_insecure_credentials=os.name != "nt")
        await restarted.start()
        client = await connect(tmp_path, authority=authority)
        try:
            result, terminal = await client.wait_task(task.task_id, timeout_s=3)
            assert terminal and result["status"] == "FAILED_RECOVERY" and result["error"] == "CONTRACT_INCOMPATIBLE", result
            info = await client.get_info()
            assert info.core_ready and not info.serving_ready
            assert restarted._conn.execute("SELECT status,binding_incarnation FROM capability_instances").fetchone() == ("FAILED", 1)
            assert restarted._conn.execute("SELECT COUNT(*) FROM invocations").fetchone()[0] == 1
        finally:
            await client.aclose()
            await restarted.close()
    asyncio.run(scenario())
