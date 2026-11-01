"""Signed activation plans, installation ownership and delegation over IPC."""

from dataclasses import replace
import json

import pytest

from agent_meta_runtime.adapters.store.authority import load_grant_row, _insert_grant
from agent_meta_runtime.adapters.store.uow import execute_command
from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.deadline import Deadline
from agent_meta_runtime.domain.errors import StableError, ErrorCode
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.sdk import AgentMetaClient, LocalTransport, CommandAuthority, decode_command, encode_command, sign_command
from test_local_server import _put_bytes, make_envelope, run_env
from test_public_package_contract import Bundle


async def prepare(env, *, scope_realm=None, body_variant=None):
    bundle = Bundle()
    capability = "capability://example.model"
    descriptor = {
        "capability_id": capability, "descriptor_revision": 1,
        "artifact_id": bundle.manifest["package_artifact_id"], "placement": "isolated_process",
        "trust_class": "trusted_candidate", "operations": [], "provides": [], "requires": [],
    }
    bundle.manifest["capability_descriptor_artifact_ids"] = [bundle.doc(descriptor)]
    requests = [{"permission": permission, "scope": {"realm_id": scope_realm or env.realm,
        "targets": [{"type": "CAPABILITY", "id": capability}]}}
        for permission in ("capability.invoke", "model.invoke")]
    bundle.manifest["grant_requests_artifact_id"] = bundle.doc({"schema": "harness-grant-requests/v1", "requests": requests})
    manifest = bundle.sign()
    for raw in list(bundle.blobs.values()):
        await _put_bytes(env, raw, "code")
    sdk = AgentMetaClient(LocalTransport(env.client), authority=env.authority)
    installed = await sdk.install_harness(realm_id=env.realm, actor_id=env.authority.actor_id,
        package_name=bundle.meta.name, package_version=bundle.meta.version,
        manifest_artifact_id=manifest, package_artifact_id=bundle.manifest["package_artifact_id"])
    body = bundle.manifest["composition_template_artifact_id"]
    if body_variant:
        candidate = {"schema": "composition/v1", "realm_id": env.realm, "wiring": [], "slots": {
            "model": {"capability_id": capability, "descriptor_revision": 1,
                      "artifact_id": descriptor["artifact_id"], "criticality": "REQUIRED",
                      "degradation_policy": "REJECT_TASK"}}}
        if body_variant == "foreign":
            candidate["slots"]["model"]["capability_id"] = "capability://another.package"
            foreign = {**descriptor, "capability_id": "capability://another.package"}
            env.conn.execute("INSERT INTO capabilities(capability_id,descriptor_revision,artifact_id,descriptor_json,created_at_us) VALUES (?,1,?,?,1)",
                             (foreign["capability_id"], foreign["artifact_id"], canonical_json(foreign)))
            env.conn.commit()
        elif body_variant == "code":
            candidate["slots"]["model"]["artifact_id"] = env.input_artifact
        elif body_variant == "realm":
            candidate["realm_id"] = "realm://other"
        body = await _put_bytes(env, canonical_json(candidate), "composition")
    before = env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0]
    envelope = await sdk.prepare_harness_activation(realm_id=env.realm, actor_id=env.authority.actor_id,
        harness_id=installed.resource["harness_id"], composition_body_artifact_id=body, grant_requests=requests)
    assert env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0] == before
    return sdk, decode_command(envelope)


def test_activation_delegates_a_signed_batch_and_replays_without_reissuing_grants(tmp_path):
    async def test(env):
        sdk, envelope = await prepare(env, body_variant="valid")
        result = await sdk.execute_command("agent_meta.public.v1.Harness.Activate", encode_command(envelope))
        assert len(result.resource["grant_ids"]) == 2
        parent = load_grant_row(env.conn, env.authority.authority_grant_id)
        for grant_id in result.resource["grant_ids"]:
            grant = load_grant_row(env.conn, grant_id)
            assert grant.parent_grant_id == parent.grant_id
            assert grant.issuer_id == env.authority.actor_id
            assert grant.subject_id.startswith("principal://service/")
            assert not grant.delegable
            assert grant.delegation_depth == parent.delegation_depth - 1
            assert grant.scope.targets[0].type == "CAPABILITY"
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses WHERE action_id=? AND use_kind='command'", (envelope.command_id,)).fetchone()[0] == 1
        delegate_key = "command://" + envelope.command_id.split("://", 1)[1]
        assert env.conn.execute("SELECT COUNT(*) FROM authority_uses WHERE action_id=? AND use_kind='delegate'", (delegate_key,)).fetchone()[0] == 1
        env.conn.execute("UPDATE authority_grants SET status='REVOKED' WHERE grant_id=?", (parent.grant_id,))
        env.conn.commit()
        replay = await sdk.execute_command("agent_meta.public.v1.Harness.Activate", encode_command(envelope))
        assert replay == result
        assert env.conn.execute("SELECT COUNT(*) FROM compositions").fetchone()[0] == 2
        assert env.conn.execute("SELECT COUNT(*) FROM authority_grants WHERE parent_grant_id=?", (parent.grant_id,)).fetchone()[0] == 2
    run_env(test, tmp_path)


@pytest.mark.parametrize("variant", ["plan", "grant_hash", "missing_meta", "missing_serving", "stale_meta", "stale_serving", "foreign", "code", "realm", "cannot_delegate", "cannot_issue_permission", "non_root"])
def test_activation_rejects_expansion_or_stale_plans_atomically(tmp_path, variant):
    async def test(env):
        sdk, envelope = await prepare(env,
            body_variant=variant if variant in {"foreign", "code", "realm"} else None)
        payload = dict(envelope.payload)
        authority = env.authority
        if variant == "plan":
            payload["plan_hash"] = "0" * 64
        elif variant == "grant_hash":
            payload["grant_request_hash"] = "0" * 64
        elif variant == "missing_meta":
            envelope = replace(envelope, expected_meta_revision=None)
        elif variant == "missing_serving":
            payload.pop("expected_serving_revision")
        elif variant == "stale_meta":
            envelope = replace(envelope, expected_meta_revision=envelope.expected_meta_revision - 1)
        elif variant == "stale_serving":
            payload["expected_serving_revision"] += 1
        elif variant in {"cannot_delegate", "cannot_issue_permission", "non_root"}:
            parent = load_grant_row(env.conn, authority.authority_grant_id)
            permissions = parent.permissions - ({"authority.delegate"} if variant == "cannot_delegate" else {"model.invoke"} if variant == "cannot_issue_permission" else set())
            subject = parent.subject_id if variant != "non_root" else env.conn.execute("SELECT principal_id FROM principals WHERE kind='SERVICE'").fetchone()[0]
            grant = replace(parent, grant_id="grant://" + new_uuid7(), parent_grant_id=parent.grant_id,
                            subject_id=subject, permissions=frozenset(permissions))
            seed = decode_command(canonical_json(make_envelope(env.realm, "task.submit/v1", {})))
            execute_command(env.conn, seed, lambda txn: (_insert_grant(txn, grant) or {}), deadline=Deadline.after(5_000_000))
            authority = CommandAuthority(subject, grant.grant_id, env.authority.signer)
            envelope = replace(envelope, actor_id=subject, authority_grant_id=grant.grant_id,
                               expected_meta_revision=env.conn.execute("SELECT current_meta_revision FROM realms").fetchone()[0])
        envelope = sign_command(replace(envelope, payload=payload), authority)
        tables = ["compositions", "authority_grants", "authority_uses", "outbox", "harness_installation_history"]
        before = {name: env.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        with pytest.raises(StableError) as denied:
            await sdk.execute_command("agent_meta.public.v1.Harness.Activate", encode_command(envelope))
        assert denied.value.code in {ErrorCode.AUTHORITY_DENIED, ErrorCode.INVALID_ARGUMENT, ErrorCode.REVISION_CONFLICT, ErrorCode.CONTRACT_INCOMPATIBLE}
        expected_issue = {"foreign": "composition.foreign_capability:model", "code": "composition.code_mismatch:model",
                          "realm": "composition.realm_or_schema"}.get(variant)
        if expected_issue:
            assert expected_issue in denied.value.details["issues"]
        if variant == "cannot_issue_permission":
            assert denied.value.details["dimension"] == "PERMISSIONS"
        assert {name: env.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables} == before
        assert env.conn.execute("SELECT status FROM harness_installations").fetchone()[0] == "INSTALLED"
    run_env(test, tmp_path)


def test_install_rejects_foreign_realm_grants_before_any_activation(tmp_path):
    async def test(env):
        tables = ("compositions", "authority_grants", "harness_installations", "outbox")
        before = {name: env.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        with pytest.raises(StableError) as denied:
            await prepare(env, scope_realm="realm://other")
        assert denied.value.code == ErrorCode.FAILED_PRECONDITION
        assert "grant_requests.realm_mismatch" in denied.value.details["issues"]
        assert {name: env.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables} == before
    run_env(test, tmp_path)
