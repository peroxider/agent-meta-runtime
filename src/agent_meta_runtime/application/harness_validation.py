"""Read-only validation of content-addressed Harness packages.

Dependencies are supplied by the composition root. No filesystem extraction,
module import, store mutation or execution is performed by this service.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any, Callable, Mapping

from ..domain.ampak import AmpakError, decode_package
from ..domain.authority import PERMISSIONS, Scope, ScopeTarget
from ..domain.canonical import canonical_json, sha256_hex
from ..domain.compatibility import EFFECT_REGISTRY, TRUST_PLACEMENT, validate as validate_composition
from ..domain.errors import StableError
from ..domain.harness import (
    contract_fingerprint, is_artifact_id, manifest_signature_preimage,
    range_allows, validate_loop_policy, validate_manifest,
)
from ..domain.harness_source import audit_harness_sources
from ..domain.ids import validate_id
from ..domain.context_contract import context_profile_references, policy_schema_references
from ..domain.provider_profile import load_profile

RESOLVED_CONTRACT_VERSIONS = {
    "public_api": "1.9.0", "harness_contract": "1.1.0", "capability_contract": "1.0.0",
}


class _Invalid(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate JSON key")
        result[key] = value
    return result


def validate_harness_package(
    manifest_artifact_id: str,
    *,
    read_artifact: Callable[[str], bytes],
    verify_signature: Callable[[bytes, bytes, bytes], bool],
    backend_features: Mapping[str, str],
    trusted_publishers: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Return a deterministic report, including stable fail-closed issues.

    Trusted publisher fingerprints are explicitly configured by the operator.
    A self-signed key cannot authorize its own execution placement. EMULATED
    features cannot satisfy a package's required production constraints.
    """
    issues: set[str] = set()
    contents: dict[str, bytes] = {}
    permissions: set[str] = set()
    features: list[str] = []
    trust_class = "trusted_candidate"
    fingerprint = ""

    def read(ref: str) -> bytes:
        if not is_artifact_id(ref):
            raise _Invalid("invalid artifact id")
        if ref not in contents:
            if len(contents) >= 1024:
                raise _Invalid("too many referenced artifacts")
            raw = read_artifact(ref)
            if not isinstance(raw, bytes) or sha256_hex(raw) != ref.rsplit("/", 1)[1]:
                raise _Invalid("artifact hash mismatch")
            contents[ref] = raw
        return contents[ref]

    def document(ref: str) -> dict:
        raw = read(ref)
        if len(raw) > 16 * 1024 * 1024:
            raise _Invalid("JSON artifact exceeds limit")
        body = json.loads(raw, object_pairs_hook=_object)
        if not isinstance(body, dict) or canonical_json(body) != raw:
            raise _Invalid("expected canonical JSON object")
        return body

    def reference(label: str, ref: str, *, json_object: bool = True):
        try:
            return document(ref) if json_object else read(ref)
        except (LookupError, ValueError, TypeError, UnicodeError, OSError, StableError):
            issues.add(f"artifact.invalid:{label}")
            return None

    manifest = reference("manifest", manifest_artifact_id)
    if manifest is not None:
        issues.update(validate_manifest(manifest))
    if manifest is None or issues:
        return _report(manifest_artifact_id, issues, contents, permissions, features, trust_class, fingerprint, backend_features)

    for key, version in RESOLVED_CONTRACT_VERSIONS.items():
        if not range_allows(manifest[f"{key}_range"], version):
            issues.add(f"contract.incompatible:{key}")
    features = manifest["required_backend_features"]
    for feature in features:
        if backend_features.get(feature) != "SUPPORTED":
            issues.add(f"backend.feature_unavailable:{feature}")

    publisher = reference("publisher", manifest["publisher_identity_artifact_id"], json_object=False)
    signature = reference("signature", manifest["signature_artifact_id"], json_object=False)
    if publisher is not None and signature is not None:
        if len(publisher) != 32 or len(signature) != 64 or not verify_signature(publisher, manifest_signature_preimage(manifest), signature):
            issues.add("manifest.signature_invalid")
        elif sha256_hex(publisher) in trusted_publishers:
            trust_class = "builtin_or_signed"

    provenance = reference("provenance", manifest["build_provenance_artifact_id"])
    policy = reference("loop_policy", manifest["loop_policy_artifact_id"])
    if policy is not None:
        issues.update(validate_loop_policy(policy))
    grants = reference("grant_requests", manifest["grant_requests_artifact_id"])
    if grants is not None:
        if set(grants) != {"schema", "requests"} or grants.get("schema") != "harness-grant-requests/v1" or not isinstance(grants.get("requests"), list):
            issues.add("grant_requests.schema")
        else:
            for index, grant in enumerate(grants["requests"]):
                try:
                    if not isinstance(grant, dict) or set(grant) - {"permission", "scope", "expires_at_us", "max_uses"}:
                        raise _Invalid("grant fields")
                    permission = grant["permission"]
                    if permission not in PERMISSIONS or permission.startswith(("authority.", "harness.", "runtime.")):
                        raise _Invalid("privileged grant")
                    scope = grant["scope"]
                    if set(scope) != {"realm_id", "targets"} or not isinstance(scope["targets"], list) or not scope["targets"]:
                        raise _Invalid("scope")
                    parsed = Scope(scope["realm_id"], tuple(ScopeTarget(**target) for target in scope["targets"]))
                    if any(target.type == "REALM_ALL" for target in parsed.targets):
                        raise _Invalid("Harness requests must be resource scoped")
                    for limit in ("expires_at_us", "max_uses"):
                        value = grant.get(limit)
                        if value is not None and (type(value) is not int or value <= 0):
                            raise _Invalid("grant limit")
                    permissions.add(permission)
                except (KeyError, TypeError, ValueError):
                    issues.add(f"grant_requests.invalid:{index}")

    package_raw = reference("package", manifest["package_artifact_id"], json_object=False)
    package = None
    if package_raw is not None:
        try:
            package, files = decode_package(package_raw)
            issues.update(audit_harness_sources(files))
            provider_ref = package.package.runtime_constraints.get("provider_profile_artifact_id")
            if provider_ref is not None:
                try:
                    load_profile(provider_ref, read)
                except (LookupError, ValueError, TypeError, StableError):
                    issues.add("provider_profile.invalid")
            if (package.package.name, package.package.version) != (manifest["package_name"], manifest["package_version"]):
                issues.add("package.identity_mismatch")
            if package.package.artifact_kind != "harness":
                issues.add("package.kind_mismatch")
            for field in ("contract_artifact_id", "dependency_lock_artifact_id", "build_provenance_artifact_id"):
                ref = getattr(package.package, field)
                if ref is None:
                    issues.add(f"package.missing:{field}")
                else:
                    reference(f"package.{field}", ref, json_object=field != "dependency_lock_artifact_id")
            for ref in (*package.package.state_schema_artifact_ids, *package.package.migration_artifact_ids):
                reference("package.schema_or_migration", ref)
            context_ref = package.package.runtime_constraints.get("context_profile_artifact_id")
            if context_ref is not None:
                context = reference("context_profile", context_ref)
                if context is not None:
                    try:
                        profile, refs = context_profile_references(read(context_ref))
                        for ref in refs:
                            reference("context_resource", ref)
                        policy, schemas = policy_schema_references(read(profile["policy_artifact_id"]))
                        for ref in schemas:
                            reference("context_normalizer", ref)
                    except (ValueError, TypeError, KeyError, StableError):
                        issues.add("context_profile.invalid")
            module, separator, symbol = package.package.entrypoint.partition(":")
            module_path = module.replace(".", "/") + ".py"
            if not separator or not symbol.isidentifier() or not module or not all(part.isidentifier() for part in module.split(".")) or module_path not in files:
                issues.add("package.entrypoint_invalid")
            else:
                # Parse without importing: package validation must never execute
                # even a top-level statement or a decorator in consumer code.
                try:
                    tree = ast.parse(files[module_path], filename=module_path)
                    if not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol for node in tree.body):
                        issues.add("package.entrypoint_missing")
                except (SyntaxError, ValueError, UnicodeError):
                    issues.add("package.entrypoint_invalid")
            if package.package.build_provenance_artifact_id != manifest["build_provenance_artifact_id"]:
                issues.add("package.provenance_mismatch")
        except (AmpakError, ValueError, TypeError, UnicodeError):
            issues.add("package.invalid")

    descriptors = {}
    for index, ref in enumerate(manifest["capability_descriptor_artifact_ids"]):
        descriptor = reference(f"descriptor.{index}", ref)
        if descriptor is None:
            continue
        try:
            capability = descriptor["capability_id"]
            revision = descriptor["descriptor_revision"]
            if not isinstance(capability, str) or not capability.startswith("capability://") or type(revision) is not int or revision < 1:
                raise _Invalid("descriptor identity")
            validate_id(capability)
            key = (capability, revision)
            if key in descriptors:
                raise _Invalid("duplicate descriptor")
            descriptors[key] = descriptor
            reference(f"descriptor.{index}.code", descriptor["artifact_id"], json_object=False)
            if descriptor["artifact_id"] != manifest["package_artifact_id"]:
                issues.add(f"descriptor.foreign_code:{index}")
            if descriptor["placement"] not in TRUST_PLACEMENT[trust_class]:
                issues.add(f"descriptor.placement_unsafe:{index}")
            if descriptor.get("trust_class", trust_class) != trust_class:
                issues.add(f"descriptor.trust_mismatch:{index}")
            if "runtime_constraints" in descriptor and not isinstance(descriptor["runtime_constraints"], dict):
                raise _Invalid("descriptor runtime constraints must be an object")
            operations = descriptor.get("operations", [])
            if not isinstance(operations, list):
                raise _Invalid("operations must be an array")
            seen_operations = set()
            for operation in operations:
                if not isinstance(operation, dict):
                    raise _Invalid("operation must be an object")
                operation_id = operation.get("operation_id")
                if not isinstance(operation_id, str) or not operation_id or operation_id in seen_operations:
                    raise _Invalid("operation id must be unique")
                seen_operations.add(operation_id)
                for direction in ("input", "output"):
                    reference(f"descriptor.{index}.{operation_id}.{direction}_schema", operation.get(f"{direction}_schema_artifact_id"))
                for field, allowed in (("effects", EFFECT_REGISTRY), ("required_permissions", PERMISSIONS)):
                    values = operation.get(field)
                    if not isinstance(values, list) or not all(isinstance(value, str) for value in values) or len(set(values)) != len(values) or not set(values) <= allowed:
                        raise _Invalid("unknown effect or permission")
                if operation.get("idempotency") not in ("PURE", "KEYED", "NONE") or operation.get("retry_semantics") not in ("NEVER", "SAME_KEY_TRANSIENT"):
                    raise _Invalid("operation retry/idempotency contract")
            for field in ("provides", "requires"):
                interfaces = descriptor.get(field, [])
                if not isinstance(interfaces, list) or not all(isinstance(item, dict) for item in interfaces):
                    raise _Invalid("interfaces must be an array of objects")
            if "state" in descriptor and descriptor["state"] is not None:
                reference(f"descriptor.{index}.state_schema", descriptor["state"]["schema_artifact_id"])
        except (KeyError, TypeError, ValueError):
            issues.add(f"descriptor.invalid:{index}")

    composition = reference("composition_template", manifest["composition_template_artifact_id"])
    if composition is not None:
        slots = composition.get("slots")
        if composition.get("schema") != "composition/v1" or not isinstance(slots, dict) or not isinstance(composition.get("wiring"), list):
            issues.add("composition.invalid")
        else:
            for name, slot in slots.items():
                if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) or not isinstance(slot, dict) or not isinstance(slot.get("capability_id"), str) or type(slot.get("descriptor_revision")) is not int:
                    issues.add(f"composition.slot_invalid:{name}")
                elif (slot["capability_id"], slot["descriptor_revision"]) not in descriptors:
                    issues.add(f"composition.descriptor_missing:{name}")
                elif slot.get("placement") not in TRUST_PLACEMENT[trust_class]:
                    issues.add(f"composition.placement_unsafe:{name}")
                if isinstance(slot, dict) and slot.get("artifact_id") != manifest["package_artifact_id"]:
                    issues.add(f"composition.foreign_code:{name}")
            try:
                # Reuse the Runtime's interface/wiring/criticality/feature checks,
                # while passing the verifier's trust decision instead of trusting
                # a package-supplied classification.
                catalog = {key: dict(value, trust_class=trust_class,
                    runtime_constraints={**value.get("runtime_constraints", {}), "trust_class": trust_class})
                    for key, value in descriptors.items()}
                compatible = validate_composition(
                    {"schema": "composition/v1", "slots": {}, "wiring": []},
                    composition, catalog,
                    {"features": [key for key, level in backend_features.items() if level == "SUPPORTED"]},
                    artifact_index=contents, new_grant_permissions=permissions,
                )
                issues.update(f"composition.{item.code}:{item.path}" for item in compatible.issues if item.severity == "ERROR")
            except (KeyError, TypeError, ValueError, AttributeError):
                issues.add("composition.invalid")
    if provenance is not None and package is not None:
        if not isinstance(provenance.get("schema"), str):
            issues.add("provenance.schema")
        if provenance.get("source_files") != {path: sha256_hex(content) for path, content in files.items()}:
            issues.add("provenance.source_mismatch")
        if "dependency_lock_artifact_id" in provenance and provenance["dependency_lock_artifact_id"] != package.package.dependency_lock_artifact_id:
            issues.add("provenance.lock_mismatch")
    if composition is not None and isinstance(composition.get("slots"), dict) and grants is not None and isinstance(grants.get("requests"), list):
        for grant in grants["requests"]:
            if not isinstance(grant, dict) or not isinstance(grant.get("scope"), dict):
                continue
            scope = grant["scope"]
            if scope.get("realm_id") != composition.get("realm_id"):
                issues.add("grant_requests.realm_mismatch")
            for target in scope.get("targets", []) if isinstance(scope.get("targets"), list) else []:
                if isinstance(target, dict) and target.get("type") == "CAPABILITY" and not any(key[0] == target.get("id") for key in descriptors):
                    issues.add("grant_requests.foreign_capability")

    fingerprint = contract_fingerprint(
        public_api_range=manifest["public_api_range"], harness_contract_range=manifest["harness_contract_range"],
        capability_contract_range=manifest["capability_contract_range"], artifact_format=manifest["artifact_format"],
        loop_policy_sha256=manifest["loop_policy_artifact_id"].rsplit("/", 1)[1],
        backend_features=features, resolved_contract_versions=RESOLVED_CONTRACT_VERSIONS,
    )
    return _report(manifest_artifact_id, issues, contents, permissions, features, trust_class, fingerprint, backend_features)


def _report(manifest_id, issues, contents, permissions, features, trust_class, fingerprint, backend_features):
    plan = {
        "manifest_artifact_id": manifest_id, "artifact_ids": sorted(contents),
        "resolved_contract_versions": RESOLVED_CONTRACT_VERSIONS,
        "backend_features": dict(backend_features), "trust_class": trust_class,
    }
    return {
        "manifest_artifact_id": manifest_id, "valid": not issues, "issues": sorted(issues),
        "resolved_contract_versions": dict(RESOLVED_CONTRACT_VERSIONS),
        "trust_class": trust_class, "requested_permissions": sorted(permissions),
        "required_backend_features": sorted(features), "contract_fingerprint": fingerprint,
        "verified_artifact_ids": sorted(contents),
        "plan_hash": sha256_hex(canonical_json(plan)),
    }


def validate_activation_composition(body, manifest, *, realm_id, read_artifact, trust_class, backend_features, builtin_catalog=None):
    """Validate actual activation bytes against installation-owned descriptors.

    A signed template is not evidence that an arbitrary replacement body is
    compatible. Builtins come from the Runtime's explicit composition root.
    """
    issues = set()
    catalog = dict(builtin_catalog or {})
    artifacts = set()
    for reference in manifest["capability_descriptor_artifact_ids"]:
        descriptor = json.loads(read_artifact(reference))
        key = (descriptor["capability_id"], descriptor["descriptor_revision"])
        catalog[key] = dict(descriptor, trust_class=trust_class,
                            runtime_constraints={**descriptor.get("runtime_constraints", {}), "trust_class": trust_class})
    for descriptor in catalog.values():
        artifacts.add(descriptor["artifact_id"])
    if body.get("schema") != "composition/v1" or body.get("realm_id") != realm_id:
        issues.add("composition.realm_or_schema")
    try:
        for name, slot in body.get("slots", {}).items():
            descriptor = catalog.get((slot.get("capability_id"), slot.get("descriptor_revision")))
            if descriptor is None:
                issues.add(f"composition.foreign_capability:{name}")
            elif slot.get("artifact_id") != descriptor["artifact_id"]:
                issues.add(f"composition.code_mismatch:{name}")
        grants = json.loads(read_artifact(manifest["grant_requests_artifact_id"]))["requests"]
        for item in grants:
            if item["scope"]["realm_id"] != realm_id:
                issues.add("grant_requests.realm_mismatch")
            for target in item["scope"]["targets"]:
                if target["type"] == "CAPABILITY" and not any(key[0] == target["id"] for key in catalog):
                    issues.add("grant_requests.foreign_capability")
        compatible = validate_composition(
            {"schema": "composition/v1", "slots": {}, "wiring": []}, body, catalog,
            {"features": [name for name, level in backend_features.items() if level == "SUPPORTED"]},
            artifact_index=artifacts, new_grant_permissions={item["permission"] for item in grants},
        )
        issues.update(f"composition.{item.code}:{item.path}" for item in compatible.issues if item.severity == "ERROR")
    except (TypeError, KeyError, ValueError, AttributeError):
        issues.add("composition.invalid")
    return sorted(issues)
