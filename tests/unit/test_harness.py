"""Step 07 gate: Harness manifest v1 and loop policy validation (§41.60.2)."""

from __future__ import annotations

import hashlib
import json

from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.harness import (
    ARTIFACT_ID_RE,
    HOST_LOOP_CEILING,
    MANIFEST_FIELDS,
    PACKAGE_NAME_RE,
    contract_fingerprint,
    manifest_signature_preimage,
    range_allows,
    validate_grant_requests,
    validate_loop_policy,
    validate_manifest,
)
from agent_meta_runtime.adapters.crypto import Ed25519KeyPair

A1 = "artifact://sha256/" + hashlib.sha256(b"a1").hexdigest()
A2 = "artifact://sha256/" + hashlib.sha256(b"a2").hexdigest()
A3 = "artifact://sha256/" + hashlib.sha256(b"a3").hexdigest()


def valid_manifest():
    return {
        "schema": "harness-package/v1",
        "package_name": "org.example.harness",
        "package_version": "0.1.0",
        "package_artifact_id": A1,
        "publisher_identity_artifact_id": A2,
        "signature_artifact_id": A3,
        "public_api_range": ">=1.0.0 <2.0.0",
        "harness_contract_range": ">=1.0.0 <2.0.0",
        "capability_contract_range": ">=1.0.0 <2.0.0",
        "artifact_format": "AMPAK1",
        "capability_descriptor_artifact_ids": sorted([A1, A2]),
        "composition_template_artifact_id": A1,
        "grant_requests_artifact_id": A2,
        "loop_policy_artifact_id": A3,
        "required_backend_features": ["model.invoke"],
        "optional_backend_features": [],
        "build_provenance_artifact_id": A1,
    }


def valid_loop_policy():
    return {
        "schema": "harness-loop-policy/v1",
        "stop_on_tool_error": True,
        "max_turns": 8,
        "max_steps": 40,
        "max_model_calls": 8,
    }


def test_manifest_happy_path():
    assert validate_manifest(valid_manifest()) == ()


def test_manifest_missing_and_unknown_fields():
    manifest = valid_manifest()
    del manifest["package_version"]
    manifest["extra"] = 1
    issues = validate_manifest(manifest)
    assert "manifest.missing:package_version" in issues
    assert "manifest.unknown_field:extra" in issues
    assert issues == tuple(sorted(issues))


def test_manifest_field_rules():
    manifest = valid_manifest()
    manifest["package_name"] = "Bad_Name"
    manifest["package_version"] = "1.0"
    manifest["public_api_range"] = ">=x"
    manifest["artifact_format"] = "ZIP"
    manifest["package_artifact_id"] = "sha256:abc"
    issues = validate_manifest(manifest)
    assert "manifest.package_name" in issues
    assert "manifest.package_version" in issues
    assert "manifest.public_api_range" in issues
    assert "manifest.artifact_format" in issues
    assert "manifest.artifact_id:package_artifact_id" in issues


def test_manifest_arrays_must_be_byte_sorted_and_deduped():
    manifest = valid_manifest()
    manifest["required_backend_features"] = ["z.feat", "a.feat"]
    assert "manifest.array_unsorted_or_dupes:required_backend_features" in validate_manifest(
        manifest
    )
    manifest["required_backend_features"] = ["a.feat", "a.feat"]
    assert "manifest.array_unsorted_or_dupes:required_backend_features" in validate_manifest(
        manifest
    )
    manifest["required_backend_features"] = ["a.feat"]
    first, second = sorted([A1, A2])
    manifest["capability_descriptor_artifact_ids"] = [second, first]
    assert "manifest.array_unsorted_or_dupes:capability_descriptor_artifact_ids" in (
        validate_manifest(manifest)
    )


def test_signature_preimage_excludes_signature_field():
    manifest = valid_manifest()
    pre = manifest_signature_preimage(manifest)
    assert pre.startswith(b"agent-meta-harness-manifest-v1\x00")
    body = {k: v for k, v in manifest.items() if k != "signature_artifact_id"}
    assert pre.endswith(canonical_json(body))
    # tampering with signature_artifact_id does not change the preimage
    tampered = dict(manifest, signature_artifact_id=A2)
    assert manifest_signature_preimage(tampered) == pre


def test_signature_verifies_with_ed25519():
    manifest = valid_manifest()
    keypair = Ed25519KeyPair.generate()
    signature = keypair.sign(manifest_signature_preimage(manifest))
    from agent_meta_runtime.adapters.crypto import verify_signature

    assert verify_signature(keypair.public_bytes_raw(), manifest_signature_preimage(manifest), signature)
    assert not verify_signature(keypair.public_bytes_raw(), b"tampered", signature)


def test_loop_policy_valid_and_ceiling_enforced():
    assert validate_loop_policy(valid_loop_policy()) == ()
    over = valid_loop_policy()
    over["max_turns"] = HOST_LOOP_CEILING["max_turns"] + 1
    assert "loop_policy.exceeds_host_ceiling:max_turns" in validate_loop_policy(over)
    bad = valid_loop_policy()
    bad["max_steps"] = 0
    del bad["stop_on_tool_error"]
    bad["custom"] = 1
    issues = validate_loop_policy(bad)
    assert "loop_policy.max_steps" in issues
    assert "loop_policy.stop_on_tool_error" in issues
    assert "loop_policy.unknown_field:custom" in issues


def test_contract_fingerprint_is_stable_jcs_sha256():
    kwargs = dict(
        public_api_range=">=1.0.0 <2.0.0",
        harness_contract_range=">=1.0.0 <2.0.0",
        capability_contract_range=">=1.0.0 <2.0.0",
        artifact_format="AMPAK1",
        loop_policy_sha256=sha256_hex(b"policy"),
        backend_features=["model.invoke", "b.feat", "a.feat"],
        resolved_contract_versions={"public_api": "1.0.0", "harness_contract": "1.0.0"},
    )
    fp1 = contract_fingerprint(**kwargs)
    fp2 = contract_fingerprint(**kwargs)
    assert fp1 == fp2 == sha256_hex(
        canonical_json(
            {
                "artifact_format": "AMPAK1",
                "backend_features": ["a.feat", "b.feat", "model.invoke"],
                "capability_contract_range": ">=1.0.0 <2.0.0",
                "harness_contract_range": ">=1.0.0 <2.0.0",
                "loop_policy_sha256": sha256_hex(b"policy"),
                "public_api_range": ">=1.0.0 <2.0.0",
                "resolved_contract_versions": {
                    "harness_contract": "1.0.0",
                    "public_api": "1.0.0",
                },
            }
        )
    )
    assert contract_fingerprint(**{**kwargs, "backend_features": ["a.feat"]}) != fp1


def test_range_allows():
    assert range_allows(">=1.0.0 <2.0.0", "1.0.0")
    assert range_allows(">=1.0.0 <2.0.0", "1.5.2")
    assert not range_allows(">=1.0.0 <2.0.0", "2.0.0")
    assert not range_allows(">=1.0.0 <2.0.0", "0.9.9")


def test_grant_requests_document():
    assert validate_grant_requests(
        {"schema": "harness-grant-requests/v1", "requests": [{"permission": "model.invoke"}]}
    ) == ()
    issues = validate_grant_requests({"schema": "wrong", "requests": []})
    assert "grant_requests.schema" in issues and "grant_requests.requests" in issues
    issues = validate_grant_requests(
        {"schema": "harness-grant-requests/v1", "requests": [{"scope": "x"}, 5]}
    )
    assert "grant_requests.permission:0" in issues
    assert "grant_requests.request:1" in issues


def test_id_and_name_regexes():
    import hashlib as _h

    assert ARTIFACT_ID_RE.fullmatch("artifact://sha256/" + _h.sha256(b"x").hexdigest())
    assert not ARTIFACT_ID_RE.fullmatch("artifact://sha256/XYZ")
    assert PACKAGE_NAME_RE.fullmatch("org.example.harness")
    assert PACKAGE_NAME_RE.fullmatch("seed-harness")
    assert not PACKAGE_NAME_RE.fullmatch("-lead")
    assert not PACKAGE_NAME_RE.fullmatch("Bad")
