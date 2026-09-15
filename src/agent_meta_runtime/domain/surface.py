"""Capability Surface Artifact and authority fingerprint (§41.37, §41.59.1).

The surface is a model-visible snapshot, not an authorization credential.
Cache key is fixed as
``(realm_id, composition_id, authority_fingerprint, backend_profile_hash)``;
the fingerprint is the SHA-256 of a JCS object over the root principal
identity, the authority history boundary and the sorted grant projection that
is still valid at Task acceptance. Any authority, composition or backend
profile change yields a new cache key and never mutates an existing surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .canonical import canonical_json, sha256_hex

__all__ = [
    "GrantProjectionEntry",
    "authority_fingerprint",
    "SurfaceOperation",
    "surface_cache_key",
    "build_surface_artifact",
]


@dataclass(frozen=True, slots=True)
class GrantProjectionEntry:
    """One still-valid grant projection row for fingerprint computation."""

    grant_id: str
    permission: str
    canonical_scope: str  # canonical_scope = JCS of the scope JSON
    not_before_us: int | None
    expires_at_us: int | None
    remaining_uses: int | None

    def to_json(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "permission": self.permission,
            "canonical_scope": self.canonical_scope,
            "not_before_us": self.not_before_us,
            "expires_at_us": self.expires_at_us,
            "remaining_uses": self.remaining_uses,
        }


def authority_fingerprint(
    *,
    principal_id: str,
    epoch_id: str,
    authority_history_boundary_meta_revision: int,
    grant_projection: Iterable[GrantProjectionEntry],
) -> str:
    """SHA-256 over the §41.59.1 fingerprint object.

    ``authority_history_boundary_meta_revision`` is the max ``meta_revision``
    over ``authority_grant_history`` and ``authority_uses`` rows reachable from
    the principal (0 when none exist). The principal identity is always
    projected — never an empty stand-in for implicit authority.
    """

    entries = sorted(
        grant_projection,
        key=lambda e: (
            e.grant_id,
            e.permission,
            e.canonical_scope,
            str(e.not_before_us),
            str(e.expires_at_us),
            str(e.remaining_uses),
        ),
    )
    payload = {
        "principal_id": principal_id,
        "epoch_id": epoch_id,
        "authority_history_boundary_meta_revision": authority_history_boundary_meta_revision,
        "grants": [entry.to_json() for entry in entries],
    }
    return sha256_hex(canonical_json(payload))


@dataclass(frozen=True, slots=True)
class SurfaceOperation:
    """One operation descriptor in the surface artifact."""

    operation_id: str
    contract_version: str
    input_schema_hash: str
    output_schema_hash: str
    description: str
    effects: tuple[str, ...]
    idempotency: str
    retry_semantics: str
    required_permissions: tuple[str, ...]
    scope: Mapping[str, Any]
    availability_reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "contract_version": self.contract_version,
            "input_schema_hash": self.input_schema_hash,
            "output_schema_hash": self.output_schema_hash,
            "description": self.description,
            "effects": sorted(self.effects),
            "idempotency": self.idempotency,
            "retry_semantics": self.retry_semantics,
            "required_permissions": sorted(self.required_permissions),
            "scope": dict(self.scope),
            "availability_reason": self.availability_reason,
        }


def surface_cache_key(
    *,
    realm_id: str,
    composition_id: str,
    authority_fingerprint_hex: str,
    backend_profile_hash: str,
) -> tuple[str, str, str, str]:
    """The fixed surface cache key tuple (§41.59.1)."""

    return (realm_id, composition_id, authority_fingerprint_hex, backend_profile_hash)


def build_surface_artifact(operations: Iterable[SurfaceOperation]) -> tuple[bytes, str]:
    """Build the JCS surface payload and its ArtifactId (§41.37).

    Operations are sorted by ``operation_id``; the payload hash is the
    canonical ArtifactId preimage. Authority-filtered operations must not be
    passed in at all — the caller filters before building.
    """

    payload = {
        "format_version": 1,
        "operations": [
            op.to_json() for op in sorted(operations, key=lambda op: op.operation_id)
        ],
    }
    body = canonical_json(payload)
    artifact_id = "artifact://sha256/" + sha256_hex(body)
    return body, artifact_id
