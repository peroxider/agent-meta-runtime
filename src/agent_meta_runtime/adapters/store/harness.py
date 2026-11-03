"""Harness installation lifecycle store use cases (§41.60).

Install registers an already-CAS-staged package with ``status=INSTALLED``
— no Grant, Composition revision, Task or Backend request is created.
Activate composes the shared mutators: one immutable Composition
revision, the operator's scoped Grants, the desired CAS and a reconcile
outbox entry; serving is never touched directly. The Reconciler settles
activation/deactivation in the same terminal transaction that moves
serving (:func:`settle_harness_for_cutover`). Uninstall is terminal and
refuses any residual reference. The ``UNIQUE(realm_id, package_name,
package_version)`` key plus the installation triggers enforce the
§41.60.5 no-resurrect rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.authority import (
    GrantConstraints,
    Scope,
    ScopeTarget,
)
from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_fact_event
from ...domain.ids import new_uuid7
from ...ports.repositories import FactAppendRequest, OutboxRequest
from .authority import CreateGrantRequest, RevokeGrantRequest, create_grant, revoke_grant
from .composition import (
    CompositionCreateRequest,
    SetDesiredRequest,
    _cas_update,
    _next_meta_revision,
    create_composition,
    set_desired,
)
from .uow import _SqliteStoreTransaction

if TYPE_CHECKING:
    import sqlite3

__all__ = [
    "ActivateHarnessRequest",
    "DeactivateHarnessRequest",
    "InstallHarnessRequest",
    "ScopedGrantSpec",
    "UninstallHarnessRequest",
    "activate_harness",
    "deactivate_harness",
    "get_harness_row",
    "install_harness",
    "list_harness_rows",
    "settle_harness_for_cutover",
    "uninstall_harness",
]

def _append_fact(
    txn: "_SqliteStoreTransaction",
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> str:
    validate_fact_event(entity_type, event_type, 1, dict(payload))
    return txn.append_fact(
        FactAppendRequest(
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            schema_version=1,
            payload=dict(payload),
            occurred_at_us=txn.recorded_at_us,
            actor_id=txn._envelope.actor_id,
        )
    )


def _installation(txn: "_SqliteStoreTransaction", harness_id: str) -> tuple:
    row = txn._conn.execute(
        "SELECT harness_id, realm_id, package_name, package_version, status,"
        " active_composition_id, package_artifact_id FROM harness_installations WHERE harness_id = ?",
        (harness_id,),
    ).fetchone()
    if row is None:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="harness installation not found",
            details={"harness_id": harness_id},
        )
    if row[1] != txn._envelope.realm_id:
        raise StableError(
            code=ErrorCode.NOT_FOUND,
            message="harness installation belongs to another realm",
        )
    return row


def _write_history(
    txn: "_SqliteStoreTransaction",
    *,
    harness_id: str,
    status: str,
    composition_id: str | None,
    source_fact_id: str,
) -> None:
    txn._conn.execute(
        "INSERT INTO harness_installation_history(harness_id, meta_revision,"
        " status, composition_id, source_fact_id) VALUES (?, ?, ?, ?, ?)",
        (
            harness_id,
            _next_meta_revision(txn),
            status,
            composition_id,
            source_fact_id,
        ),
    )


def _revoke_scoped_grants(txn: "_SqliteStoreTransaction", harness_id: str, *, exclude_composition_id=None) -> list[str]:
    """Retire all recorded activation generations except an explicit survivor."""

    row = txn._conn.execute(
        "SELECT payload_json FROM facts WHERE entity_type = 'harness'"
        " AND entity_id = ? AND event_type = 'harness_activated'"
        " ORDER BY seq DESC",
        (harness_id,),
    ).fetchall()
    grant_ids: set[str] = set()
    for (payload_json,) in row:
        payload = json_loads(payload_json)
        if exclude_composition_id is not None and payload.get("composition_id") == exclude_composition_id:
            continue
        grant_ids.update(gid for gid in payload.get("grant_ids", []) if isinstance(gid, str))
    if not grant_ids:
        return []
    revoked = []
    for grant_id in sorted(grant_ids):
        active = txn._conn.execute(
            "SELECT 1 FROM authority_grants WHERE grant_id = ? AND status = 'ACTIVE'",
            (grant_id,),
        ).fetchone()
        if active is not None:
            revoke_grant(
                RevokeGrantRequest(grant_id=grant_id, reason_code="harness_lifecycle")
            )(txn)
            revoked.append(grant_id)
    return revoked


def json_loads(raw: bytes | str) -> dict[str, Any]:
    import json

    return dict(json.loads(bytes(raw).decode("utf-8")))


# -- Install (§41.60.3) --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstallHarnessRequest:
    realm_id: str
    package_name: str
    package_version: str
    manifest_artifact_id: str
    package_artifact_id: str
    contract_fingerprint: str
    installed_by: str
    verified_artifact_ids: tuple[str, ...] = ()


def install_harness(request: InstallHarnessRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        existing = conn.execute(
            "SELECT harness_id, package_artifact_id, manifest_artifact_id, status"
            " FROM harness_installations WHERE realm_id = ? AND package_name = ?"
            " AND package_version = ?",
            (request.realm_id, request.package_name, request.package_version),
        ).fetchone()
        if existing is not None:
            if existing[3] == "UNINSTALLED":
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION,
                    message="package was uninstalled; history never revives",
                    details={
                        "package_name": request.package_name,
                        "package_version": request.package_version,
                    },
                )
            if (
                existing[1] == request.package_artifact_id
                and existing[2] == request.manifest_artifact_id
            ):
                # equivalent install content: idempotent success (§41.60.3)
                return {
                    "harness_id": existing[0],
                    "status": existing[3],
                    "package_name": request.package_name,
                    "package_version": request.package_version,
                }
            raise StableError(
                code=ErrorCode.IDEMPOTENCY_CONFLICT,
                message="same package name/version already installed with a different"
                        " hash; publish a new version",
                details={
                    "package_name": request.package_name,
                    "package_version": request.package_version,
                },
            )
        harness_id = "harness://" + str(new_uuid7())
        now_us = txn.recorded_at_us
        conn.execute(
            "INSERT INTO harness_installations(harness_id, realm_id, package_name,"
            " package_version, package_artifact_id, manifest_artifact_id,"
            " contract_fingerprint, status, active_composition_id, installed_by,"
            " installed_at_us, updated_at_us)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'INSTALLED', NULL, ?, ?, ?)",
            (
                harness_id,
                request.realm_id,
                request.package_name,
                request.package_version,
                request.package_artifact_id,
                request.manifest_artifact_id,
                request.contract_fingerprint,
                request.installed_by,
                now_us,
                now_us,
            ),
        )
        fact_id = _append_fact(
            txn,
            entity_type="harness",
            entity_id=harness_id,
            event_type="harness_installed",
            payload={
                "package_name": request.package_name,
                "package_version": request.package_version,
                "contract_fingerprint": request.contract_fingerprint,
                "artifact_ids": list(request.verified_artifact_ids),
            },
        )
        _write_history(
            txn, harness_id=harness_id, status="INSTALLED",
            composition_id=None, source_fact_id=fact_id,
        )
        return {
            "harness_id": harness_id,
            "status": "INSTALLED",
            "package_name": request.package_name,
            "package_version": request.package_version,
        }

    return mutator


# -- Activate (§41.60.4) -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScopedGrantSpec:
    subject_id: str
    permissions: frozenset[str]
    scope_targets: tuple[ScopeTarget, ...]
    expires_at_us: int | None = None
    max_uses: int | None = None


@dataclass(frozen=True, slots=True)
class ActivateHarnessRequest:
    harness_id: str
    composition_body: Mapping[str, Any]
    issuer_grant_id: str
    scoped_grants: tuple[ScopedGrantSpec, ...] = ()
    plan_hash: str = ""
    grant_request_hash: str = ""


def activate_harness(request: ActivateHarnessRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        row = _installation(txn, request.harness_id)
        if row[4] == "UNINSTALLED":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="UNINSTALLED is terminal; history never revives",
            )
        conn = txn._conn
        next_revision = int(
            conn.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM compositions"
                " WHERE realm_id = ?",
                (txn._envelope.realm_id,),
            ).fetchone()[0]
        )
        composition_id = "composition://" + str(new_uuid7())
        create_composition(
            CompositionCreateRequest(
                realm_id=txn._envelope.realm_id,
                body=dict(request.composition_body),
                created_by=txn._envelope.actor_id,
                revision=next_revision,
                composition_id=composition_id,
            )
        )(txn)

        grant_ids: list[str] = []
        for spec in request.scoped_grants:
            receipt = create_grant(CreateGrantRequest(
                issuer_grant_id=request.issuer_grant_id,
                subject_id=spec.subject_id,
                permissions=spec.permissions,
                scope=Scope(
                    realm_id=txn._envelope.realm_id, targets=spec.scope_targets
                ),
                constraints=GrantConstraints(
                    expires_at_us=spec.expires_at_us, max_uses=spec.max_uses
                ),
                delegable=False,
            ))(txn)
            grant_ids.append(receipt["grant_id"])

        refs = conn.execute(
            "SELECT desired_cas FROM composition_refs WHERE realm_id = ?",
            (txn._envelope.realm_id,),
        ).fetchone()
        desired_cas = int(refs[0]) if refs else 0
        set_desired(
            SetDesiredRequest(
                realm_id=txn._envelope.realm_id,
                revision=next_revision,
                expected_cas=desired_cas,
            )
        )(txn)

        fact_id = _append_fact(
            txn,
            entity_type="harness",
            entity_id=request.harness_id,
            event_type="harness_activated",
            payload={
                "phase": "requested",
                "composition_id": composition_id,
                "revision": str(next_revision),
                "plan_hash": request.plan_hash,
                "grant_request_hash": request.grant_request_hash,
                "grant_ids": grant_ids,
            },
        )
        _write_history(
            txn, harness_id=request.harness_id, status="INSTALLED",
            composition_id=composition_id, source_fact_id=fact_id,
        )
        txn.enqueue_outbox(
            OutboxRequest(
                kind="RECONCILE_REQUEST",
                dedupe_key=f"harness-activate:{request.harness_id}:{next_revision}",
                payload={
                    "harness_id": request.harness_id,
                    "composition_id": composition_id,
                    "revision": next_revision,
                },
                available_at_us=txn.recorded_at_us,
            )
        )
        return {
            "harness_id": request.harness_id,
            "composition_id": composition_id,
            "revision": next_revision,
            "grant_ids": grant_ids,
            "status": "INSTALLED",  # serving switch is the Reconciler's job
        }

    return mutator


# -- Reconciler settlement (§41.60.4) ------------------------------------------


def fail_harness_activation(composition_id: str, *, reason_code: str):
    """Revoke only this failed candidate's Grants, never the old serving set."""
    def mutator(txn):
        owner = txn._conn.execute(
            "SELECT DISTINCT h.harness_id,h.status FROM harness_installations h JOIN harness_installation_history x "
            "ON x.harness_id=h.harness_id WHERE x.composition_id=? AND h.realm_id=?",
            (composition_id, txn._envelope.realm_id),
        ).fetchone()
        if owner is None:
            return {}
        serving = txn._conn.execute("SELECT c.composition_id FROM composition_refs r JOIN compositions c ON c.realm_id=r.realm_id AND c.revision=r.serving_revision WHERE r.realm_id=?", (txn._envelope.realm_id,)).fetchone()
        if serving is not None and serving[0] == composition_id:
            return {}  # a failed rebind does not impersonate a new activation
        requested = txn._conn.execute(
            "SELECT payload_json FROM facts WHERE realm_id=? AND entity_type='harness' AND entity_id=? AND event_type='harness_activated' "
            "AND json_extract(CAST(payload_json AS TEXT),'$.phase')='requested' "
            "AND json_extract(CAST(payload_json AS TEXT),'$.composition_id')=? ORDER BY seq DESC LIMIT 1",
            (txn._envelope.realm_id, owner[0], composition_id),
        ).fetchone()
        if requested is None:
            return {}
        revoked = []
        for grant_id in json_loads(requested[0]).get("grant_ids", []):
            status = txn._conn.execute("SELECT status FROM authority_grants WHERE grant_id=?", (grant_id,)).fetchone()
            if status is not None and status[0] == "ACTIVE":
                revoke_grant(RevokeGrantRequest(grant_id, reason_code="harness_activation_failed"))(txn)
                revoked.append(grant_id)
        fact_id = _append_fact(txn, entity_type="harness", entity_id=owner[0], event_type="harness_activated",
            payload={"phase": "failed", "composition_id": composition_id, "reason_code": reason_code, "revoked_grant_ids": revoked})
        _write_history(txn, harness_id=owner[0], status=owner[1], composition_id=composition_id, source_fact_id=fact_id)
        return {"revoked_grant_ids": revoked}
    return mutator


def settle_harness_for_cutover(realm_id: str, composition_id: str | None):
    """Settle harness activation for the composition that just reached serving.

    Marks the requesting installation ACTIVE, the previously ACTIVE
    installation INACTIVE, revokes the old scoped grants and writes both
    history rows plus the ``harness_activated`` fact — all in the caller's
    terminal transaction. With ``composition_id=None`` (drain cycle) the
    realm's ACTIVE installation is marked INACTIVE instead. No-op when the
    composition has no harness owner.
    """

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        conn = txn._conn
        if composition_id is None:
            # drain cycle: serving converged to the revision-0 sentinel
            previous = conn.execute(
                "SELECT harness_id, active_composition_id FROM harness_installations"
                " WHERE realm_id = ? AND status = 'ACTIVE'",
                (realm_id,),
            ).fetchone()
            if previous is None:
                return {}
            conn.execute(
                "UPDATE harness_installations SET status = 'INACTIVE',"
                " active_composition_id = NULL, updated_at_us = ?"
                " WHERE harness_id = ?",
                (txn.recorded_at_us, previous[0]),
            )
            revoked = _revoke_scoped_grants(txn, previous[0])
            fact_id = _append_fact(
                txn,
                entity_type="harness",
                entity_id=previous[0],
                event_type="harness_deactivated",
                payload={
                    "phase": "serving-drained",
                    "composition_id": previous[1],
                    "revoked_grant_ids": revoked,
                },
            )
            _write_history(
                txn, harness_id=previous[0], status="INACTIVE",
                composition_id=None, source_fact_id=fact_id,
            )
            return {"harness_id": previous[0], "revoked_grant_ids": revoked}
        pending = conn.execute(
            "SELECT h.harness_id, h.status, h.active_composition_id"
            " FROM harness_installation_history hist"
            " JOIN harness_installations h ON h.harness_id = hist.harness_id"
            " WHERE hist.composition_id = ? AND h.realm_id = ?"
            " ORDER BY hist.meta_revision DESC LIMIT 1",
            (composition_id, realm_id),
        ).fetchone()
        if pending is None:
            return {}
        harness_id, status, active_composition_id = pending
        if status == "ACTIVE" and active_composition_id == composition_id:
            return {"harness_id": harness_id, "settled": "already-active"}
        if status == "UNINSTALLED":
            return {"harness_id": harness_id, "settled": "skipped-uninstalled"}

        retired_grants = _revoke_scoped_grants(txn, harness_id, exclude_composition_id=composition_id)

        conn.execute(
            "UPDATE harness_installations SET status = 'ACTIVE',"
            " active_composition_id = ?, updated_at_us = ? WHERE harness_id = ?",
            (composition_id, txn.recorded_at_us, harness_id),
        )
        fact_id = _append_fact(
            txn,
            entity_type="harness",
            entity_id=harness_id,
            event_type="harness_activated",
            payload={
                "phase": "serving",
                "composition_id": composition_id,
                "revoked_grant_ids": retired_grants,
            },
        )
        _write_history(
            txn, harness_id=harness_id, status="ACTIVE",
            composition_id=composition_id, source_fact_id=fact_id,
        )

        previous = conn.execute(
            "SELECT harness_id, active_composition_id FROM harness_installations"
            " WHERE realm_id = ? AND status = 'ACTIVE' AND harness_id != ?",
            (realm_id, harness_id),
        ).fetchone()
        revoked: list[str] = list(retired_grants)
        if previous is not None:
            conn.execute(
                "UPDATE harness_installations SET status = 'INACTIVE',"
                " active_composition_id = NULL, updated_at_us = ?"
                " WHERE harness_id = ?",
                (txn.recorded_at_us, previous[0]),
            )
            revoked.extend(_revoke_scoped_grants(txn, previous[0]))
            prev_fact = _append_fact(
                txn,
                entity_type="harness",
                entity_id=previous[0],
                event_type="harness_deactivated",
                payload={
                    "phase": "superseded",
                    "composition_id": previous[1],
                    "revoked_grant_ids": revoked,
                },
            )
            _write_history(
                txn, harness_id=previous[0], status="INACTIVE",
                composition_id=None, source_fact_id=prev_fact,
            )
        return {"harness_id": harness_id, "revoked_grant_ids": revoked}

    return mutator


# -- Deactivate (§41.60.4) -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeactivateHarnessRequest:
    harness_id: str
    reason_code: str = "operator_deactivate"


def deactivate_harness(request: DeactivateHarnessRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        row = _installation(txn, request.harness_id)
        if row[4] != "ACTIVE":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="only the ACTIVE harness can be deactivated",
                details={"status": row[4]},
            )
        conn = txn._conn
        refs = conn.execute(
            "SELECT serving_revision, desired_cas FROM composition_refs"
            " WHERE realm_id = ?",
            (txn._envelope.realm_id,),
        ).fetchone()
        serving_revision, desired_cas = int(refs[0]), int(refs[1])
        serving_composition = conn.execute(
            "SELECT composition_id FROM compositions WHERE realm_id = ? AND revision = ?",
            (txn._envelope.realm_id, serving_revision),
        ).fetchone()
        if serving_composition is None or serving_composition[0] != row[5]:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="harness does not own the current serving composition",
            )
        # desired CAS → revision 0 sentinel; the Reconciler drains serving→0
        _cas_update(
            txn,
            column="desired_revision",
            cas_column="desired_cas",
            revision=0,
            expected_cas=desired_cas,
            new_status="PENDING",
        )
        fact_id = _append_fact(
            txn,
            entity_type="harness",
            entity_id=request.harness_id,
            event_type="harness_deactivated",
            payload={
                "phase": "requested",
                "reason_code": request.reason_code,
                "composition_id": row[5],
            },
        )
        _write_history(
            txn, harness_id=request.harness_id, status="ACTIVE",
            composition_id=row[5], source_fact_id=fact_id,
        )
        txn.enqueue_outbox(
            OutboxRequest(
                kind="RECONCILE_REQUEST",
                dedupe_key=f"harness-deactivate:{request.harness_id}:{desired_cas}",
                payload={
                    "harness_id": request.harness_id,
                    "composition_id": None,
                    "revision": 0,
                },
                available_at_us=txn.recorded_at_us,
            )
        )
        return {
            "harness_id": request.harness_id,
            "desired_revision": 0,
            "status": row[4],  # stays ACTIVE until serving converges to 0
        }

    return mutator


# -- Uninstall (§41.60.5) ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UninstallHarnessRequest:
    harness_id: str
    reason_code: str = "operator_uninstall"


def uninstall_harness(request: UninstallHarnessRequest):
    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        row = _installation(txn, request.harness_id)
        if row[4] not in ("INSTALLED", "INACTIVE"):
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="only INSTALLED/INACTIVE installations can be uninstalled",
                details={"status": row[4]},
            )
        conn = txn._conn
        # Only the target installation's typed ownership closure pins it.
        # A new serving generation must not prevent removal of a drained old
        # version. The checks remain in this same command transaction.
        pins = conn.execute("""
            WITH owned_compositions(composition_id) AS (
                SELECT hist.composition_id FROM harness_installation_history hist
                JOIN compositions c ON c.composition_id=hist.composition_id
                WHERE hist.harness_id=:harness AND c.realm_id=:realm
                UNION
                SELECT c.composition_id FROM compositions c WHERE c.realm_id=:realm
                AND EXISTS (SELECT 1 FROM json_each(c.body_json,'$.slots') slot
                    WHERE CASE WHEN slot.type='object' THEN json_extract(slot.value,'$.artifact_id') END=:package)
            ), owned_capabilities(capability_id,descriptor_revision) AS (
                SELECT capability_id,descriptor_revision FROM capabilities WHERE artifact_id=:package
            )
            SELECT
                EXISTS (SELECT 1 FROM composition_refs r JOIN compositions c ON c.realm_id=r.realm_id
                    AND c.revision IN (r.desired_revision,r.serving_revision,r.realized_revision)
                    WHERE r.realm_id=:realm AND c.composition_id IN owned_compositions),
                (SELECT COUNT(*) FROM tasks WHERE realm_id=:realm AND serving_composition_id IN owned_compositions
                    AND status NOT IN ('SUCCEEDED','FAILED','FAILED_RECOVERY','TIMED_OUT','CANCELLED')),
                (SELECT COUNT(*) FROM capability_instances i WHERE i.realm_id=:realm
                    AND i.status IN ('ACTIVE','INSTANTIATING','DRAINING')
                    AND (i.composition_id IN owned_compositions OR EXISTS (SELECT 1 FROM owned_capabilities c
                        WHERE c.capability_id=i.capability_id AND c.descriptor_revision=i.descriptor_revision))),
                (SELECT COUNT(*) FROM managed_states WHERE owner_id IN (:harness,:package)
                    OR owner_id IN owned_compositions OR owner_id IN (SELECT capability_id FROM owned_capabilities)),
                (SELECT COUNT(*) FROM effect_intents e JOIN actions a ON a.action_id=e.action_id
                    WHERE a.composition_id IN owned_compositions AND e.status NOT IN ('SUCCEEDED','FAILED','COMPENSATED'))
            """, {"realm": txn._envelope.realm_id, "harness": request.harness_id, "package": row[6]}).fetchone()
        for count, kind in zip(pins, ("current Composition", "non-terminal Task", "active Capability instance", "State owner", "unsettled Effect")):
            if count:
                raise StableError(code=ErrorCode.FAILED_PRECONDITION,
                    message=f"installation still has a {kind} reference; uninstall refused", details={"count": str(count)})
        revoked = _revoke_scoped_grants(txn, request.harness_id)
        conn.execute(
            "UPDATE harness_installations SET status = 'UNINSTALLED',"
            " updated_at_us = ? WHERE harness_id = ?",
            (txn.recorded_at_us, request.harness_id),
        )
        fact_id = _append_fact(
            txn,
            entity_type="harness",
            entity_id=request.harness_id,
            event_type="harness_uninstalled",
            payload={
                "reason_code": request.reason_code,
                "revoked_grant_ids": revoked,
            },
        )
        _write_history(
            txn, harness_id=request.harness_id, status="UNINSTALLED",
            composition_id=None, source_fact_id=fact_id,
        )
        return {
            "harness_id": request.harness_id,
            "status": "UNINSTALLED",
            "revoked_grant_ids": revoked,
        }

    return mutator


# -- pure queries (Harness.Get / Harness.List) ---------------------------------


def get_harness_row(conn: "sqlite3.Connection", harness_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT harness_id, realm_id, package_name, package_version,"
        " package_artifact_id, manifest_artifact_id, contract_fingerprint,"
        " status, active_composition_id, installed_by, installed_at_us,"
        " updated_at_us FROM harness_installations WHERE harness_id = ?",
        (harness_id,),
    ).fetchone()
    if row is None:
        return None
    keys = (
        "harness_id", "realm_id", "package_name", "package_version",
        "package_artifact_id", "manifest_artifact_id", "contract_fingerprint",
        "status", "active_composition_id", "installed_by", "installed_at_us",
        "updated_at_us",
    )
    return dict(zip(keys, row))


def list_harness_rows(
    conn: "sqlite3.Connection",
    realm_id: str,
    *,
    status: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    sql = (
        "SELECT harness_id, package_name, package_version, status,"
        " active_composition_id, installed_at_us FROM harness_installations"
        " WHERE realm_id = ?"
    )
    params: list[Any] = [realm_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY package_name, package_version, harness_id LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))
    return [
        {
            "harness_id": r[0],
            "package_name": r[1],
            "package_version": r[2],
            "status": r[3],
            "active_composition_id": r[4],
            "installed_at_us": r[5],
        }
        for r in conn.execute(sql, tuple(params)).fetchall()
    ]
