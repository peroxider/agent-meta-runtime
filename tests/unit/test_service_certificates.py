"""Actual bootstrap public chain + scoped Service key; no Root key at worker."""

from dataclasses import asdict
import json
import os

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.credentials import service_signing_authority
from agent_meta_runtime.adapters.crypto import verify_signature
from agent_meta_runtime.adapters.store.connection import connect_store
from agent_meta_runtime.adapters.store.gc import collect_marks
from agent_meta_runtime.adapters.store.service_certificates import load_service_execution_trust
from agent_meta_runtime.domain.canonical import now_us, sha256_hex
from agent_meta_runtime.domain.execution_tokens import ExecutionTokenBinding, issue_execution_token
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.interfaces.cli.init import run_init


def initialized(root):
    return run_init(root, insecure_dev_credential_file=os.name != "nt")


def test_fresh_bootstrap_certificate_and_actual_service_signer_verify_without_token_storage(tmp_path):
    report = initialized(tmp_path)
    conn, cas = connect_store(tmp_path / "meta.db"), FilesystemCas(tmp_path)
    try:
        trust = load_service_execution_trust(conn, cas, realm_id=report.realm_id, now_us=now_us())
        assert trust.certificate_artifact_id == report.details["service_certificate_artifact_id"]
        assert trust.certificate_artifact_id.rsplit("/", 1)[1] in collect_marks(conn)
        cert = json.loads(trust.certificate)["certificate"]
        assert cert["permissions"] == ["capability.invoke", "model.invoke"]
        root_public = bytes.fromhex(json.loads(conn.execute("SELECT public_identity_json FROM principals WHERE kind='OPERATOR_ROOT'").fetchone()[0])["public_key_hex"])
        assert root_public != trust.service_public_key
        signer = service_signing_authority(tmp_path, expected_public_key=trust.service_public_key, allow_insecure=os.name != "nt")
        now = now_us()
        binding = ExecutionTokenBinding("negotiated-session", report.realm_id, report.epoch_id,
            report.details["root_principal_id"], "action://" + new_uuid7(), "model.invoke", sha256_hex(b"scope"),
            {"steps": 1, "cost_microunits": 0}, frozenset({"model.invoke"}), deadline_at_us=now + 1_000_000)
        payload = {"token_version": 1, "token_id": new_uuid7(), "backend_session_id": binding.backend_session_id,
            "realm_id": binding.realm_id, "actor_id": binding.actor_id, "action_id": binding.action_id,
            "effect_kind": binding.effect_kind, "target_scope_hash": binding.target_scope_hash,
            "resource_ceiling": dict(binding.resource_ceiling), "issued_at_us": now, "expires_at_us": now + 1_000_000,
            "nonce": "explicit-test-nonce-0123456789"}
        raw = issue_execution_token(payload, service_principal_id=trust.service_principal_id, signer=signer)
        before = conn.total_changes
        audit = trust.verifier.verify(raw, request_id="real-backend-request", request_payload_hash=sha256_hex(b"request"), binding=binding, now_us=now)
        assert conn.total_changes == before and audit.certificate_artifact_id == trust.certificate_artifact_id
        assert set(asdict(audit)) == {"token_id", "payload_hash", "service_public_key_id", "certificate_artifact_id", "request_id", "expires_at_us"}
        assert not any(raw in path.read_bytes() for path in cas.artifacts_dir.rglob("*") if path.is_file())
        assert raw not in conn.execute("SELECT group_concat(CAST(payload_json AS TEXT)) FROM facts").fetchone()[0].encode()
        message = b"Service-only signing test"
        assert verify_signature(trust.service_public_key, message, signer(message))
        assert not verify_signature(root_public, message, signer(message))
    finally:
        conn.close()


def test_certificate_corruption_prevents_reinitialization_without_rotating_keys(tmp_path):
    initialized(tmp_path)
    conn, cas = connect_store(tmp_path / "meta.db"), FilesystemCas(tmp_path)
    try:
        trust = load_service_execution_trust(conn, cas, realm_id="realm://main")
        manifest = json.loads(conn.execute("SELECT manifest_json FROM artifacts WHERE artifact_id=?", (trust.certificate_artifact_id,)).fetchone()[0])
        cas.absolute_path(manifest["storage_relpath"]).write_bytes(b"corrupted public certificate")
        before = conn.total_changes
        with pytest.raises(StableError) as error:
            initialized(tmp_path)
        assert error.value.code == ErrorCode.INTEGRITY_ERROR and conn.total_changes == before
        assert conn.execute("SELECT COUNT(*) FROM principals").fetchone()[0] == 2
    finally:
        conn.close()


def test_expired_certificate_does_not_authorize_execution_but_remains_publicly_verifiable(tmp_path):
    initialized(tmp_path)
    conn, cas = connect_store(tmp_path / "meta.db"), FilesystemCas(tmp_path)
    try:
        trust = load_service_execution_trust(conn, cas, realm_id="realm://main")
        with pytest.raises(StableError) as error:
            load_service_execution_trust(conn, cas, realm_id="realm://main", now_us=trust.expires_at_us)
        assert error.value.code == ErrorCode.KEY_UNAVAILABLE
        assert load_service_execution_trust(conn, cas, realm_id="realm://main").certificate == trust.certificate
    finally:
        conn.close()


def test_service_signer_rejects_a_key_different_from_the_committed_public_identity(tmp_path):
    initialized(tmp_path)
    signer = service_signing_authority(tmp_path, expected_public_key=b"x" * 32, allow_insecure=os.name != "nt")
    with pytest.raises(StableError) as error:
        signer(b"do not sign")
    assert error.value.code == ErrorCode.KEY_UNAVAILABLE
