"""Capability Surface resolution inside the Task-accept transaction (§41.59.1).

The cache key is ``(realm_id, composition_id, authority_fingerprint,
backend_profile_hash)``. Within the accept transaction's SQLite snapshot the
resolver reads the serving composition and the authority boundary, computes
the fingerprint, reuses a matching surface row or atomically allocates the
next ``surface_revision`` for the realm, and registers the JCS surface
artifact. Authority-filtered operations never enter the surface; grant
changes only affect later cache keys, never an existing surface row.
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.surface import (
    GrantProjectionEntry,
    SurfaceOperation,
    authority_fingerprint,
    build_surface_artifact,
)
from .authority import _GRANT_COLUMNS, _grant_from_row

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = ["resolve_or_create_surface", "authority_boundary_for_principal"]


def authority_boundary_for_principal(conn, principal_id: str) -> tuple[int, list[Any]]:
    """Return ``(boundary_meta_revision, grant_rows)`` reachable from the
    principal: the max meta revision over grant history and use counters, 0
    when the principal has no authority records (§41.59.1)."""

    rows = conn.execute(
        f"SELECT {_GRANT_COLUMNS} FROM authority_grants WHERE subject_id = ?",
        (principal_id,),
    ).fetchall()
    boundary = 0
    for row in rows:
        grant_id = row[0]
        for table in ("authority_grant_history", "authority_uses"):
            value = conn.execute(
                f"SELECT MAX(meta_revision) FROM {table} WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()[0]
            if value is not None:
                boundary = max(boundary, int(value))
    return boundary, rows


def resolve_or_create_surface(
    txn: "_SqliteStoreTransaction",
    *,
    composition_id: str,
    actor_id: str,
    backend_profile_hash: str,
) -> dict[str, Any]:
    """Resolve or create the capability surface for one Task acceptance.

    Returns ``{"surface_revision", "surface_artifact_id", "reused"}``.
    """

    conn = txn._conn
    realm_id = txn._envelope.realm_id
    now_us = txn.recorded_at_us
    realm_row = conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id = ?", (realm_id,)
    ).fetchone()
    if realm_row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="realm not found")
    epoch_id = realm_row[0]

    boundary, grant_rows = authority_boundary_for_principal(conn, actor_id)
    grants = [_grant_from_row(row) for row in grant_rows]
    valid = [
        g
        for g in grants
        if g.status == "ACTIVE"
        and (g.expires_at_us is None or g.expires_at_us > now_us)
        and (
            g.constraints.not_before_us is None or g.constraints.not_before_us <= now_us
        )
    ]

    projection: list[GrantProjectionEntry] = []
    for grant in valid:
        uses = conn.execute(
            "SELECT COUNT(*) FROM authority_uses WHERE grant_id = ?",
            (grant.grant_id,),
        ).fetchone()[0]
        max_uses = grant.constraints.max_uses
        remaining = max_uses - uses if max_uses is not None else None
        scope_text = grant.scope.canonical_bytes().decode("utf-8")
        for permission in sorted(grant.permissions):
            projection.append(
                GrantProjectionEntry(
                    grant_id=grant.grant_id,
                    permission=permission,
                    canonical_scope=scope_text,
                    not_before_us=grant.constraints.not_before_us,
                    expires_at_us=grant.constraints.expires_at_us,
                    remaining_uses=remaining,
                )
            )

    fingerprint = authority_fingerprint(
        principal_id=actor_id,
        epoch_id=epoch_id,
        authority_history_boundary_meta_revision=boundary,
        grant_projection=projection,
    )

    hit = conn.execute(
        "SELECT surface_revision, artifact_id FROM capability_surfaces WHERE"
        " realm_id = ? AND composition_id = ? AND authority_fingerprint = ?"
        " AND backend_profile_hash = ?",
        (realm_id, composition_id, fingerprint, backend_profile_hash),
    ).fetchone()
    if hit is not None:
        return {
            "surface_revision": int(hit[0]),
            "surface_artifact_id": hit[1],
            "reused": True,
        }

    comp_row = conn.execute(
        "SELECT body_json FROM compositions WHERE composition_id = ?",
        (composition_id,),
    ).fetchone()
    if comp_row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message=f"composition not found: {composition_id}",
        )
    body = json.loads(bytes(comp_row[0]).decode("utf-8"))

    operations: list[SurfaceOperation] = []
    for slot_name, slot in (body.get("slots") or {}).items():
        cap_row = conn.execute(
            "SELECT descriptor_json FROM capabilities WHERE capability_id = ?"
            " AND descriptor_revision = ?",
            (slot.get("capability_id"), slot.get("descriptor_revision")),
        ).fetchone()
        if cap_row is None:
            continue
        contract = json.loads(bytes(cap_row[0]).decode("utf-8"))
        for operation in contract.get("operations", []):
            required = set(operation.get("required_permissions", []))
            matched_scope = None
            if required:
                covering = [
                    g for g in valid if required <= g.permissions
                ]
                if not covering:
                    continue  # authority filter: operation stays out of the surface
                matched_scope = covering[0].scope
            operations.append(
                SurfaceOperation(
                    operation_id=operation.get("operation_id", slot_name),
                    contract_version=contract.get("contract_version", "1.0.0"),
                    input_schema_hash=str(
                        operation.get("input_schema_artifact_id", "")
                    ).rsplit("/", 1)[-1],
                    output_schema_hash=str(
                        operation.get("output_schema_artifact_id", "")
                    ).rsplit("/", 1)[-1],
                    description=operation.get("description", ""),
                    effects=tuple(operation.get("effects", ())),
                    idempotency=operation.get("idempotency", "NONE"),
                    retry_semantics=operation.get("retry_semantics", "NEVER"),
                    required_permissions=tuple(sorted(required)),
                    scope=matched_scope.to_json()
                    if matched_scope is not None
                    else {"realm_id": realm_id, "targets": []},
                    availability_reason="READY",
                )
            )

    artifact_body, artifact_id = build_surface_artifact(operations)
    try:
        conn.execute(
            "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
            " schema_version, created_by, created_at_us, parents_json,"
            " manifest_json, integrity_status)"
            " VALUES (?, 'capability_surface', 'application/json', ?, 1, ?, ?,"
            " ?, ?, 'VALID')",
            (
                artifact_id,
                len(artifact_body),
                actor_id,
                now_us,
                canonical_json([]),
                canonical_json({}),
            ),
        )
    except sqlite3.IntegrityError as exc:
        # Content-addressed id: an identical surface body registered by a
        # different (fingerprint, revision) is deduplicated, not an error.
        exists = conn.execute(
            "SELECT 1 FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if exists is None:
            raise StableError(
                code=ErrorCode.INTERNAL,
                message="surface artifact registration failed",
            ) from exc

    next_revision = conn.execute(
        "SELECT COALESCE(MAX(surface_revision), 0) + 1 FROM capability_surfaces"
        " WHERE realm_id = ?",
        (realm_id,),
    ).fetchone()[0]
    try:
        conn.execute(
            "INSERT INTO capability_surfaces(realm_id, surface_revision,"
            " composition_id, artifact_id, authority_fingerprint,"
            " backend_profile_hash, created_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                realm_id,
                next_revision,
                composition_id,
                artifact_id,
                fingerprint,
                backend_profile_hash,
                now_us,
            ),
        )
    except sqlite3.IntegrityError:
        # Unique cache-key collision: reuse the winner instead of duplicating.
        hit = conn.execute(
            "SELECT surface_revision, artifact_id FROM capability_surfaces WHERE"
            " realm_id = ? AND composition_id = ? AND authority_fingerprint = ?"
            " AND backend_profile_hash = ?",
            (realm_id, composition_id, fingerprint, backend_profile_hash),
        ).fetchone()
        if hit is None:  # pragma: no cover - defensive
            raise
        return {
            "surface_revision": int(hit[0]),
            "surface_artifact_id": hit[1],
            "reused": True,
        }
    return {
        "surface_revision": int(next_revision),
        "surface_artifact_id": artifact_id,
        "reused": False,
    }
