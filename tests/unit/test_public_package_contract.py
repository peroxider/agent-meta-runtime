"""Public AMPAK authoring and read-only Harness validation negatives."""

import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_meta_runtime.sdk.packages import (
    AmpakError, PackageMeta, build_manifest, canonical_json, decode_package,
    encode_package, manifest_signature_preimage, sha256_hex,
)
from agent_meta_runtime.adapters.crypto import verify_signature
from agent_meta_runtime.application.harness_validation import validate_harness_package


class Bundle:
    def __init__(self):
        self.blobs = {}
        self.key = Ed25519PrivateKey.generate()
        self.files = {"probe.py": b"raise RuntimeError('validation must not import code')\nasync def run():\n    return None\n"}
        self.meta = PackageMeta(
            name="example.harness", version="0.1.0", artifact_kind="harness",
            entrypoint="probe:run", contract_artifact_id=self.doc({"schema": "harness-contract/v1", "version": "1.1.0"}),
            dependency_lock_artifact_id=self.add(b"pinned dependencies\n"),
            state_schema_artifact_ids=(), migration_artifact_ids=(),
            runtime_constraints={}, platform_constraints={},
            build_provenance_artifact_id=self.doc({"schema": "example-provenance/v1", "source_files": {path: sha256_hex(raw) for path, raw in self.files.items()}}),
        )
        package = self.add(encode_package(build_manifest(self.meta, self.files), self.files))
        self.manifest = {
            "schema": "harness-package/v1", "package_name": self.meta.name,
            "package_version": self.meta.version, "package_artifact_id": package,
            "publisher_identity_artifact_id": self.add(self.key.public_key().public_bytes_raw()),
            "signature_artifact_id": "artifact://sha256/" + "0" * 64,
            "public_api_range": ">=1.0.0 <2.0.0", "harness_contract_range": ">=1.1.0 <2.0.0",
            "capability_contract_range": ">=1.0.0 <2.0.0", "artifact_format": "AMPAK1",
            "capability_descriptor_artifact_ids": [],
            "composition_template_artifact_id": self.doc({"schema": "composition/v1", "realm_id": "realm://main", "slots": {}, "wiring": []}),
            "grant_requests_artifact_id": self.doc({"schema": "harness-grant-requests/v1", "requests": []}),
            "loop_policy_artifact_id": self.doc({"schema": "harness-loop-policy/v1", "stop_on_tool_error": True, "max_turns": 8, "max_model_calls": 8, "max_steps": 40}),
            "required_backend_features": [], "optional_backend_features": [],
            "build_provenance_artifact_id": self.meta.build_provenance_artifact_id,
        }

    def add(self, raw):
        ref = "artifact://sha256/" + sha256_hex(raw)
        self.blobs[ref] = raw
        return ref

    def doc(self, body):
        return self.add(canonical_json(body))

    def sign(self):
        self.manifest["signature_artifact_id"] = self.add(self.key.sign(manifest_signature_preimage(self.manifest)))
        return self.doc(self.manifest)

    def validate(self, **kwargs):
        ref = self.sign()
        return validate_harness_package(ref, read_artifact=self.blobs.__getitem__, verify_signature=verify_signature, backend_features=kwargs.pop("backend_features", {}), **kwargs)

    def replace_files(self, files):
        self.files = dict(files)
        provenance = self.doc({"schema": "example-provenance/v1", "source_files": {path: sha256_hex(raw) for path, raw in self.files.items()}})
        self.meta = replace(self.meta, build_provenance_artifact_id=provenance)
        self.manifest["build_provenance_artifact_id"] = provenance
        self.manifest["package_artifact_id"] = self.add(encode_package(build_manifest(self.meta, self.files), self.files))


def test_valid_signed_bundle_is_deterministic_and_executes_nothing():
    bundle = Bundle()
    first = bundle.validate()
    assert first["valid"], first
    assert first == bundle.validate()
    assert first["trust_class"] == "trusted_candidate"
    assert len(first["plan_hash"]) == len(first["contract_fingerprint"]) == 64


@pytest.mark.parametrize("source,reason", [
    ("import agent_meta_runtime.adapters.store", "private_runtime_import"),
    ("from agent_meta_runtime.application import task_host", "private_runtime_import"),
    ("from agent_meta_runtime.sdk import _windows_peer", "private_runtime_import"),
    ("from agent_meta_runtime.sdk import *", "opaque_import"),
    ("import importlib as loader\nf = loader.import_module\nf('agent_meta_runtime.adapters.store')", "private_runtime_import"),
    ("from importlib import import_module as load\na = load\nb = a\nb(module_name)", "dynamic_import"),
    ("import builtins as b\nf = b.__import__\nf(name='agent_meta_runtime.adapters.store')", "private_runtime_import"),
    ("import sys as s\nsearch = s.path\nsearch.insert(0, 'checkout')", "import_path_mutation"),
    ("import sys\nsys.path[:] = ['checkout']", "import_path_mutation"),
    ("import sys\nsys.meta_path = []", "import_path_mutation"),
    ("import site\nsite.addsitedir('checkout')", "import_path_mutation"),
    ("from os import chdir as move\nmove('checkout')", "import_path_mutation"),
    ("import importlib\ngetattr(importlib, loader_name)('anything')", "opaque_import"),
    ("import agent_meta_runtime.sdk as api\ngetattr(api, hidden_name)", "opaque_import"),
    ("import agent_meta_runtime.sdk as api\napi._hidden()", "private_runtime_access"),
    ("import importlib\napi = importlib.import_module('agent_meta_runtime.sdk')\ngetattr(api, '_private')", "private_runtime_access"),
    ("import agent_meta_runtime.sdk\nagent_meta_runtime.adapters", "private_runtime_access"),
    ("run = eval\nrun('__import__(module)')", "opaque_import"),
    ("__builtins__['__import__'](name)", "opaque_import"),
    ("from importlib.util import spec_from_file_location as load\nload('x', 'checkout.py')", "opaque_import"),
    ("from ...outside import anything", "relative_import_escape"),
    ("def broken(:", "invalid"),
])
def test_all_package_modules_are_audited_without_importing(source, reason):
    bundle = Bundle()
    bundle.replace_files({**bundle.files, "unused/helper.py": source.encode()})
    report = bundle.validate()
    assert not report["valid"]
    assert any(item.startswith(f"package.source_{reason}:unused/helper.py:") or item == f"package.source_{reason}:unused/helper.py" for item in report["issues"]), report


def test_audit_allows_explicit_public_and_own_relative_imports_without_side_effects(tmp_path):
    bundle = Bundle()
    marker = tmp_path / "must-not-exist"
    bundle.replace_files({"probe.py": ("from agent_meta_runtime.sdk.host import HarnessAdapter\nfrom .helper import value\nfrom pathlib import Path\n" + f"Path({str(marker)!r}).write_text('executed')\n" + "def run():\n    return value\n").encode(),
        "helper.py": b"value = 1\n"})
    # A top-level relative import from a non-package module is rejected. Move
    # the supported entrypoint into an explicit AMPAK package.
    bundle.meta = replace(bundle.meta, entrypoint="own.probe:run")
    bundle.replace_files({"own/__init__.py": b"", "own/probe.py": bundle.files["probe.py"], "own/helper.py": bundle.files["helper.py"]})
    assert bundle.validate()["valid"]
    assert not marker.exists()


def test_package_cannot_vendor_runtime_or_exceed_python_source_ceiling():
    bundle = Bundle()
    bundle.replace_files({**bundle.files, "agent_meta_runtime/adapters/store.py": b"pass\n"})
    assert any(item.startswith("package.source_vendored_runtime:") for item in bundle.validate()["issues"])
    bundle.replace_files({**Bundle().files, "huge.py": b"#" + b"x" * (1024 * 1024)})
    assert "package.source_budget:huge.py" in bundle.validate()["issues"]


def test_provenance_claims_must_match_exact_payload_files_and_dependency_lock():
    bundle = Bundle()
    for changed in ({}, {"probe.py": "0" * 64}, {"probe.py": sha256_hex(bundle.files["probe.py"]), "not-in-package.py": "a" * 64}):
        provenance = bundle.doc({"schema": "example-provenance/v1", "source_files": changed})
        bundle.meta = replace(bundle.meta, build_provenance_artifact_id=provenance)
        bundle.manifest["build_provenance_artifact_id"] = provenance
        bundle.manifest["package_artifact_id"] = bundle.add(encode_package(build_manifest(bundle.meta, bundle.files), bundle.files))
        assert "provenance.source_mismatch" in bundle.validate()["issues"]
    provenance = bundle.doc({"schema": "example-provenance/v1", "source_files": {"probe.py": sha256_hex(bundle.files["probe.py"])}, "dependency_lock_artifact_id": bundle.add(b"different lock")})
    bundle.meta = replace(bundle.meta, build_provenance_artifact_id=provenance)
    bundle.manifest["build_provenance_artifact_id"] = provenance
    bundle.manifest["package_artifact_id"] = bundle.add(encode_package(build_manifest(bundle.meta, bundle.files), bundle.files))
    assert "provenance.lock_mismatch" in bundle.validate()["issues"]


def test_descriptor_cannot_claim_code_outside_its_signed_package():
    bundle = Bundle()
    descriptor = {"capability_id": "capability://example.echo", "descriptor_revision": 1,
        "artifact_id": bundle.add(b"foreign executable code"), "placement": "isolated_process", "operations": []}
    bundle.manifest["capability_descriptor_artifact_ids"] = [bundle.doc(descriptor)]
    assert "descriptor.foreign_code:0" in bundle.validate()["issues"]


def test_bad_signature_or_publisher_cannot_become_trusted():
    bundle = Bundle()
    ref = bundle.sign()
    signature_id = bundle.manifest["signature_artifact_id"]
    bundle.blobs[signature_id] = b"0" * 64
    report = validate_harness_package(ref, read_artifact=bundle.blobs.__getitem__, verify_signature=verify_signature, backend_features={})
    assert not report["valid"] and "artifact.invalid:signature" in report["issues"]
    bundle.manifest["signature_artifact_id"] = bundle.add(b"0" * 64)
    ref = bundle.doc(bundle.manifest)
    report = validate_harness_package(ref, read_artifact=bundle.blobs.__getitem__, verify_signature=verify_signature, backend_features={})
    assert "manifest.signature_invalid" in report["issues"]


@pytest.mark.parametrize("field", ["public_api", "harness_contract", "capability_contract"])
def test_disjoint_contract_range_fails(field):
    bundle = Bundle()
    bundle.manifest[field + "_range"] = ">=9.0.0 <10.0.0"
    assert f"contract.incompatible:{field}" in bundle.validate()["issues"]


def test_required_feature_emulation_and_unsupported_fail_closed():
    bundle = Bundle()
    bundle.manifest["required_backend_features"] = ["network_isolation"]
    assert "backend.feature_unavailable:network_isolation" in bundle.validate(backend_features={"network_isolation": "EMULATED"})["issues"]
    assert bundle.validate(backend_features={"network_isolation": "SUPPORTED"})["valid"]


@pytest.mark.parametrize("permission,scope", [
    ("authority.grant", {"realm_id": "realm://main", "targets": [{"type": "HARNESS", "id": "harness://a"}]}),
    ("model.invoke", {"realm_id": "realm://main", "targets": [{"type": "REALM_ALL"}]}),
    ("model.invoke", "all"),
    ("root", {}),
])
def test_privileged_or_unscoped_grant_is_rejected(permission, scope):
    bundle = Bundle()
    bundle.manifest["grant_requests_artifact_id"] = bundle.doc({"schema": "harness-grant-requests/v1", "requests": [{"permission": permission, "scope": scope}]})
    assert "grant_requests.invalid:0" in bundle.validate()["issues"]


def test_missing_artifact_and_noncanonical_json_are_invalid():
    bundle = Bundle()
    ref = bundle.sign()
    del bundle.blobs[bundle.manifest["loop_policy_artifact_id"]]
    # The storage port reports unknown artifacts as a stable error.
    from agent_meta_runtime.domain.errors import ErrorCode, StableError

    def read(artifact):
        if artifact not in bundle.blobs:
            raise StableError(code=ErrorCode.NOT_FOUND, message="missing")
        return bundle.blobs[artifact]

    report = validate_harness_package(ref, read_artifact=read, verify_signature=verify_signature, backend_features={})
    assert "artifact.invalid:loop_policy" in report["issues"]
    bundle.manifest["loop_policy_artifact_id"] = bundle.add(b'{"schema": "harness-loop-policy/v1", "schema": "other"}')
    assert "artifact.invalid:loop_policy" in bundle.validate()["issues"]


@pytest.mark.parametrize("path", ["../x", "/x", "C:/x", "a\\b", "a//b", "CON", "aux.txt", "a.", "a ", "e\u0301.py"])
def test_public_builder_rejects_portability_and_path_escapes(path):
    with pytest.raises(AmpakError):
        build_manifest(Bundle().meta, {path: b"x"})


def test_casefold_collision_and_symlink_entry_are_rejected():
    bundle = Bundle()
    with pytest.raises(AmpakError):
        build_manifest(bundle.meta, {"A.py": b"a", "a.py": b"b"})
    manifest = build_manifest(bundle.meta, bundle.files)
    bad = replace(manifest, entries=(replace(manifest.entries[0], kind="SYMLINK"),))
    with pytest.raises(AmpakError):
        encode_package(bad, bundle.files)


@pytest.mark.parametrize("corruption", ["unknown_field", "noncanonical", "boolean_version", "trailing", "content"])
def test_decoder_rejects_malleability_and_content_corruption(corruption):
    bundle = Bundle()
    raw = bundle.blobs[bundle.manifest["package_artifact_id"]]
    length = int.from_bytes(raw[7:15], "big")
    body = json.loads(raw[15:15 + length])
    suffix = raw[15 + length:]
    if corruption == "unknown_field":
        body["unknown"] = 1
    if corruption == "boolean_version":
        body["format_version"] = True
    manifest_bytes = json.dumps(body).encode() if corruption == "noncanonical" else canonical_json(body)
    tampered = b"AMPAK1\n" + len(manifest_bytes).to_bytes(8, "big") + manifest_bytes + suffix
    if corruption == "trailing":
        tampered += b"x"
    if corruption == "content":
        tampered = tampered[:-1] + bytes([tampered[-1] ^ 1])
    with pytest.raises(AmpakError):
        decode_package(tampered)


def test_unsafe_placement_is_not_authorized_by_self_signature():
    bundle = Bundle()
    descriptor = {"capability_id": "capability://example.echo", "descriptor_revision": 1, "artifact_id": bundle.manifest["package_artifact_id"], "placement": "in_process"}
    bundle.manifest["capability_descriptor_artifact_ids"] = [bundle.doc(descriptor)]
    assert "descriptor.placement_unsafe:0" in bundle.validate()["issues"]
    assert bundle.validate(trusted_publishers=frozenset({sha256_hex(bundle.key.public_key().public_bytes_raw())}))["valid"]
