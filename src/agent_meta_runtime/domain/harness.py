"""External Harness manifest v1 and loop policy validation (§41.60.2, §41.53).

Pure domain functions: no I/O, no crypto, no store access. Signature
verification and artifact retrieval live in the adapters layer. The
manifest is a JCS Artifact with a fixed required field set — fields may
neither be omitted nor added — and byte-sorted, deduplicated string
arrays. The signature preimage covers the manifest minus
``signature_artifact_id``; it proves publisher provenance only and never
grants Authority or elevates a trust class.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .canonical import canonical_json, sha256_hex
from .compatibility import parse_semver_range, semver_satisfies

__all__ = [
    "ARTIFACT_ID_RE",
    "CONTRACT_RANGES",
    "HARNESS_ARTIFACT_FORMAT",
    "HARNESS_LOOP_POLICY_SCHEMA",
    "HARNESS_MANIFEST_SCHEMA",
    "GRANT_REQUESTS_SCHEMA",
    "MANIFEST_FIELDS",
    "MANIFEST_SIGNATURE_PREIMAGE_DOMAIN",
    "PACKAGE_NAME_RE",
    "contract_fingerprint",
    "is_artifact_id",
    "manifest_signature_preimage",
    "validate_grant_requests",
    "validate_loop_policy",
    "validate_manifest",
]

HARNESS_MANIFEST_SCHEMA = "harness-package/v1"
HARNESS_LOOP_POLICY_SCHEMA = "harness-loop-policy/v1"
GRANT_REQUESTS_SCHEMA = "harness-grant-requests/v1"
HARNESS_ARTIFACT_FORMAT = "AMPAK1"
MANIFEST_SIGNATURE_PREIMAGE_DOMAIN = b"agent-meta-harness-manifest-v1\x00"

#: Contract ranges a v0.1 package must pin (§41.60.2 manifest profile).
CONTRACT_RANGES: tuple[str, str, str] = (
    "public_api_range",
    "harness_contract_range",
    "capability_contract_range",
)

MANIFEST_FIELDS: tuple[str, ...] = (
    "schema",
    "package_name",
    "package_version",
    "package_artifact_id",
    "publisher_identity_artifact_id",
    "signature_artifact_id",
    "public_api_range",
    "harness_contract_range",
    "capability_contract_range",
    "artifact_format",
    "capability_descriptor_artifact_ids",
    "composition_template_artifact_id",
    "grant_requests_artifact_id",
    "loop_policy_artifact_id",
    "required_backend_features",
    "optional_backend_features",
    "build_provenance_artifact_id",
)

_PACKAGE_NAME_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
_ARTIFACT_ID_RE = re.compile(r"artifact://sha256/[0-9a-f]{64}\Z")

#: Exposed for lint/tests; callers match with ``fullmatch``.
PACKAGE_NAME_RE = _PACKAGE_NAME_RE
ARTIFACT_ID_RE = _ARTIFACT_ID_RE

# Host hard ceilings (§41.60.2: Harness policy values may not widen them).
HOST_LOOP_CEILING = {"max_turns": 100, "max_steps": 10_000, "max_model_calls": 10_000}

_ARTIFACT_ID_FIELDS = (
    "package_artifact_id",
    "publisher_identity_artifact_id",
    "signature_artifact_id",
    "composition_template_artifact_id",
    "grant_requests_artifact_id",
    "loop_policy_artifact_id",
    "build_provenance_artifact_id",
)
_ARRAY_FIELDS = (
    "capability_descriptor_artifact_ids",
    "required_backend_features",
    "optional_backend_features",
)


def is_artifact_id(value: Any) -> bool:
    return isinstance(value, str) and _ARTIFACT_ID_RE.fullmatch(value) is not None


def _sorted_deduped(values: list[str]) -> bool:
    """Arrays must be UTF-8 byte sorted and deduplicated (§41.60.2)."""

    encoded = [v.encode("utf-8") for v in values]
    return all(a < b for a, b in zip(encoded, encoded[1:]))


def validate_manifest(manifest: Any) -> tuple[str, ...]:
    """Structural validation only; returns sorted stable issues (empty=valid)."""

    if not isinstance(manifest, Mapping):
        return ("manifest.not_object",)
    issues: list[str] = []
    present = set(manifest)
    for field in MANIFEST_FIELDS:
        if field not in present:
            issues.append(f"manifest.missing:{field}")
    for field in sorted(present - set(MANIFEST_FIELDS)):
        issues.append(f"manifest.unknown_field:{field}")
    if issues:
        return tuple(sorted(issues))

    if manifest["schema"] != HARNESS_MANIFEST_SCHEMA:
        issues.append("manifest.schema")
    if not isinstance(manifest["package_name"], str) or not _PACKAGE_NAME_RE.fullmatch(
        manifest["package_name"]
    ):
        issues.append("manifest.package_name")
    version = manifest["package_version"]
    if not isinstance(version, str):
        issues.append("manifest.package_version")
    else:
        try:
            parse_semver_range("==" + version if version else version)
        except ValueError:
            issues.append("manifest.package_version")
    for field in CONTRACT_RANGES:
        value = manifest[field]
        if not isinstance(value, str):
            issues.append(f"manifest.{field}")
            continue
        try:
            parse_semver_range(value)
        except ValueError:
            issues.append(f"manifest.{field}")
    if manifest["artifact_format"] != HARNESS_ARTIFACT_FORMAT:
        issues.append("manifest.artifact_format")
    for field in _ARTIFACT_ID_FIELDS:
        if not is_artifact_id(manifest[field]):
            issues.append(f"manifest.artifact_id:{field}")
    for field in _ARRAY_FIELDS:
        value = manifest[field]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            issues.append(f"manifest.array:{field}")
        elif not _sorted_deduped(value):
            issues.append(f"manifest.array_unsorted_or_dupes:{field}")
        elif field == "capability_descriptor_artifact_ids" and not all(
            is_artifact_id(v) for v in value
        ):
            issues.append(f"manifest.artifact_id:{field}")
    return tuple(sorted(issues))


def manifest_signature_preimage(manifest: Mapping[str, Any]) -> bytes:
    """``domain`` + JCS of the manifest minus ``signature_artifact_id``."""

    body = {k: v for k, v in manifest.items() if k != "signature_artifact_id"}
    return MANIFEST_SIGNATURE_PREIMAGE_DOMAIN + canonical_json(body)


def validate_loop_policy(
    policy: Any, *, host_ceiling: Mapping[str, int] = HOST_LOOP_CEILING
) -> tuple[str, ...]:
    """Validate ``harness-loop-policy/v1`` (§41.60.2); sorted issues.

    Values may only be stricter than the Host hard ceiling.
    """

    if not isinstance(policy, Mapping):
        return ("loop_policy.not_object",)
    issues: list[str] = []
    if policy.get("schema") != HARNESS_LOOP_POLICY_SCHEMA:
        issues.append("loop_policy.schema")
    if "stop_on_tool_error" not in policy or not isinstance(
        policy["stop_on_tool_error"], bool
    ):
        issues.append("loop_policy.stop_on_tool_error")
    for field in ("max_turns", "max_steps", "max_model_calls"):
        value = policy.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            issues.append(f"loop_policy.{field}")
        elif value > host_ceiling[field]:
            issues.append(f"loop_policy.exceeds_host_ceiling:{field}")
    for field in sorted(set(policy) - {"schema", "stop_on_tool_error",
                                       "max_turns", "max_steps", "max_model_calls"}):
        issues.append(f"loop_policy.unknown_field:{field}")
    return tuple(sorted(issues))


def validate_grant_requests(document: Any) -> tuple[str, ...]:
    """Validate the ``grant_requests_artifact_id`` JCS payload (§41.60.4)."""

    if not isinstance(document, Mapping):
        return ("grant_requests.not_object",)
    issues: list[str] = []
    if document.get("schema") != GRANT_REQUESTS_SCHEMA:
        issues.append("grant_requests.schema")
    requests = document.get("requests")
    if not isinstance(requests, list) or not requests:
        issues.append("grant_requests.requests")
    else:
        for index, request in enumerate(requests):
            if not isinstance(request, Mapping):
                issues.append(f"grant_requests.request:{index}")
                continue
            permission = request.get("permission")
            if not isinstance(permission, str) or not permission:
                issues.append(f"grant_requests.permission:{index}")
            scope = request.get("scope")
            if scope is not None and not isinstance(scope, str):
                issues.append(f"grant_requests.scope:{index}")
    return tuple(sorted(issues))


def contract_fingerprint(
    *,
    public_api_range: str,
    harness_contract_range: str,
    capability_contract_range: str,
    artifact_format: str,
    loop_policy_sha256: str,
    backend_features: list[str],
    resolved_contract_versions: Mapping[str, str],
) -> str:
    """JCS SHA-256 over ranges, artifact format, loop policy hash, sorted
    feature set and the Runtime-selected contract versions (§41.60.2)."""

    body = {
        "artifact_format": artifact_format,
        "backend_features": sorted(backend_features),
        "capability_contract_range": capability_contract_range,
        "harness_contract_range": harness_contract_range,
        "loop_policy_sha256": loop_policy_sha256,
        "public_api_range": public_api_range,
        "resolved_contract_versions": dict(sorted(resolved_contract_versions.items())),
    }
    return sha256_hex(canonical_json(body))


def range_allows(manifest_range: str, version: str) -> bool:
    """True when ``version`` satisfies the manifest's semver range."""

    return semver_satisfies(version, parse_semver_range(manifest_range))
