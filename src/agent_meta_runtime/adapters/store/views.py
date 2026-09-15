"""Revision-consistent RuntimeView reads (§41.44.2, FR-MVIEW).

``get_current_view`` reads ``realms.current_meta_revision`` and
``realms.next_seq-1`` first inside one SQLite read transaction, then reads
refs, capability surface, state bindings, authority summary and projection
checkpoints. ``get_historical_view`` resolves revision ``N`` from
``composition_ref_history``/``state_ref_history`` (latest committed ref not
after N) and returns ``NOT_FOUND`` when N is absent from ``meta_revisions``
— it never approximates to another revision. Historical views never query
Backend live state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Mapping

from ...domain.errors import ErrorCode, StableError

__all__ = ["RuntimeView", "get_current_view", "get_historical_view"]

_RECONCILE_REASON = "RECONCILE_UNKNOWN"


@dataclass(frozen=True, slots=True)
class RuntimeView:
    realm_id: str
    epoch_id: str
    meta_revision: int
    fact_boundary_seq: int
    desired_revision: int
    serving_revision: int
    realized_revision: int
    desired_composition_id: str | None
    serving_composition_id: str | None
    realized_composition_id: str | None
    reconcile_status: str
    capability_surface_revision: int | None
    capability_surface_artifact_id: str | None
    backend_profile_hash: str | None
    state_revision_bindings: Mapping[str, str] = field(default_factory=dict)
    authority_summary: Mapping[str, int] = field(default_factory=dict)
    checkpoints: Mapping[str, int] = field(default_factory=dict)
    core_ready: bool = True
    serving_ready: bool = False
    core_reasons: tuple[str, ...] = ()
    serving_reasons: tuple[str, ...] = ()
    historical: bool = False
    observed_at_us: int = 0


def _composition_id_at(
    conn, realm_id: str, revision: int
) -> str | None:
    if revision <= 0:
        return None
    row = conn.execute(
        "SELECT composition_id FROM compositions WHERE realm_id = ? AND revision = ?",
        (realm_id, revision),
    ).fetchone()
    return None if row is None else str(row[0])


def _latest_capability_surface(
    conn, realm_id: str, *, max_created_at_us: int | None = None
) -> tuple[int | None, str | None, str | None]:
    sql = (
        "SELECT surface_revision, artifact_id, backend_profile_hash"
        " FROM capability_surfaces WHERE realm_id = ?"
    )
    params: list = [realm_id]
    if max_created_at_us is not None:
        sql += " AND created_at_us <= ?"
        params.append(max_created_at_us)
    sql += " ORDER BY surface_revision DESC LIMIT 1"
    row = conn.execute(sql, tuple(params)).fetchone()
    if row is None:
        return None, None, None
    return int(row[0]), str(row[1]), str(row[2])


def _authority_summary(conn, realm_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT g.status, COUNT(*) FROM authority_grants g"
        " JOIN realms r ON g.epoch_id = r.epoch_id"
        " WHERE r.realm_id = ? GROUP BY g.status",
        (realm_id,),
    ).fetchall()
    return {str(status): int(count) for status, count in rows}


def _checkpoints(conn, realm_id: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT projection, seq FROM checkpoints WHERE realm_id = ?", (realm_id,)
    ).fetchall()
    return {str(name): int(seq) for name, seq in rows}


def _serving_readiness(reconcile_status: str) -> tuple[bool, tuple[str, ...]]:
    if reconcile_status == "READY":
        return True, ()
    return False, (_RECONCILE_REASON,)


def get_current_view(conn, realm_id: str, *, now_us: int | None = None) -> RuntimeView:
    """Read the current revision-consistent snapshot (§41.44.2)."""

    own_transaction = not conn.in_transaction
    if own_transaction:
        conn.execute("BEGIN DEFERRED")
    try:
        realm_row = conn.execute(
            "SELECT epoch_id, current_meta_revision, next_seq FROM realms"
            " WHERE realm_id = ?",
            (realm_id,),
        ).fetchone()
        if realm_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="realm not found",
                details={"realm_id": realm_id},
            )
        epoch_id, meta_revision, next_seq = realm_row
        refs = conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision,"
            " reconcile_status FROM composition_refs WHERE realm_id = ?",
            (realm_id,),
        ).fetchone()
        if refs is None:
            desired = serving = realized = 0
            reconcile_status = "PENDING"
        else:
            desired, serving, realized, reconcile_status = refs
        surface_rev, surface_artifact, backend_profile_hash = (
            _latest_capability_surface(conn, realm_id)
        )
        bindings = {
            str(state_id): str(revision_id)
            for state_id, revision_id in conn.execute(
                "SELECT state_id, current_revision_id FROM managed_states"
            ).fetchall()
        }
        serving_ready, serving_reasons = _serving_readiness(reconcile_status)
        view = RuntimeView(
            realm_id=realm_id,
            epoch_id=str(epoch_id),
            meta_revision=int(meta_revision),
            fact_boundary_seq=int(next_seq) - 1,
            desired_revision=int(desired),
            serving_revision=int(serving),
            realized_revision=int(realized),
            desired_composition_id=_composition_id_at(conn, realm_id, int(desired)),
            serving_composition_id=_composition_id_at(conn, realm_id, int(serving)),
            realized_composition_id=_composition_id_at(conn, realm_id, int(realized)),
            reconcile_status=str(reconcile_status),
            capability_surface_revision=surface_rev,
            capability_surface_artifact_id=surface_artifact,
            backend_profile_hash=backend_profile_hash,
            state_revision_bindings=bindings,
            authority_summary=_authority_summary(conn, realm_id),
            checkpoints=_checkpoints(conn, realm_id),
            core_ready=True,
            serving_ready=serving_ready,
            serving_reasons=serving_reasons,
            historical=False,
            observed_at_us=now_us if now_us is not None else time.time_ns() // 1000,
        )
        return view
    finally:
        if own_transaction:
            conn.rollback()  # read-only; release the snapshot


def get_historical_view(conn, realm_id: str, meta_revision: int) -> RuntimeView:
    """Read the view as of committed revision N; NOT_FOUND when unknown."""

    revision_row = conn.execute(
        "SELECT committed_at_us FROM meta_revisions WHERE realm_id = ? AND revision = ?",
        (realm_id, meta_revision),
    ).fetchone()
    if revision_row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="meta revision does not exist",
            details={"realm_id": realm_id, "meta_revision": str(meta_revision)},
        )
    committed_at_us = int(revision_row[0])
    realm_row = conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id = ?", (realm_id,)
    ).fetchone()
    if realm_row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="realm not found",
            details={"realm_id": realm_id},
        )
    refs = conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " reconcile_status FROM composition_ref_history"
        " WHERE realm_id = ? AND meta_revision <= ?"
        " ORDER BY meta_revision DESC LIMIT 1",
        (realm_id, meta_revision),
    ).fetchone()
    if refs is None:
        desired = serving = realized = 0
        reconcile_status = "PENDING"
    else:
        desired, serving, realized, reconcile_status = refs
    bindings_rows = conn.execute(
        "SELECT state_id, state_revision_id, MAX(meta_revision)"
        " FROM state_ref_history WHERE meta_revision <= ? GROUP BY state_id",
        (meta_revision,),
    ).fetchall()
    bindings = {str(state_id): str(rev_id) for state_id, rev_id, _ in bindings_rows}
    boundary_row = conn.execute(
        "SELECT MAX(f.seq) FROM facts f"
        " JOIN transactions t ON f.transaction_id = t.transaction_id"
        " WHERE t.realm_id = ? AND t.meta_revision <= ?",
        (realm_id, meta_revision),
    ).fetchone()
    boundary_seq = int(boundary_row[0]) if boundary_row and boundary_row[0] else 0
    surface_rev, surface_artifact, backend_profile_hash = _latest_capability_surface(
        conn, realm_id, max_created_at_us=committed_at_us
    )
    serving_ready, serving_reasons = _serving_readiness(reconcile_status)
    return RuntimeView(
        realm_id=realm_id,
        epoch_id=str(realm_row[0]),
        meta_revision=meta_revision,
        fact_boundary_seq=boundary_seq,
        desired_revision=int(desired),
        serving_revision=int(serving),
        realized_revision=int(realized),
        desired_composition_id=_composition_id_at(conn, realm_id, int(desired)),
        serving_composition_id=_composition_id_at(conn, realm_id, int(serving)),
        realized_composition_id=_composition_id_at(conn, realm_id, int(realized)),
        reconcile_status=str(reconcile_status),
        capability_surface_revision=surface_rev,
        capability_surface_artifact_id=surface_artifact,
        backend_profile_hash=backend_profile_hash,
        state_revision_bindings=bindings,
        authority_summary=_authority_summary(conn, realm_id),
        checkpoints={},
        core_ready=True,
        serving_ready=serving_ready,
        serving_reasons=serving_reasons,
        historical=True,
        observed_at_us=committed_at_us,
    )
