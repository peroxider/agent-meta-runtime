"""Evolution Promotion & Rollback store use cases (§41.43, §41.59.3).

``promote_candidate`` is the ONLY Evolution.Promote entry: it re-runs the
Artifact / Compatibility / unknown-effect / expected-serving gates inside
one transaction and, if all pass, CAS-commits the candidate composition
as the new DESIRED revision (plus audit facts). It never touches
``serving`` directly — the Reconciler performs the serving cutover.
``rollback_composition`` creates a new tracked desired transition to the
parent composition; promoted revisions are immutable and never deleted,
and State is only reverted under an explicit RESTORE_PARENT strategy
with the exact expected revisions (never implicitly).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.errors import ErrorCode, StableError
from .composition import SetDesiredRequest, _refs_row, set_desired
from .evolution import _load_json

if TYPE_CHECKING:
    from .uow import _SqliteStoreTransaction

__all__ = [
    "PromoteCandidateRequest",
    "RollbackCompositionRequest",
    "promote_candidate",
    "rollback_composition",
]

#: composition/v1 top-level keys understood by this runtime (§41.43).
_KNOWN_BODY_KEYS = frozenset({"schema", "realm_id", "slots", "policy", "states"})

_STATE_STRATEGIES = frozenset({"KEEP_COMPATIBLE", "RESTORE_PARENT"})


@dataclass(frozen=True, slots=True)
class PromoteCandidateRequest:
    realm_id: str
    candidate_id: str
    evaluation_id: str
    expected_serving_revision: int


@dataclass(frozen=True, slots=True)
class RollbackCompositionRequest:
    realm_id: str
    target_parent_id: str
    expected_serving_revision: int
    state_strategy: str = "KEEP_COMPATIBLE"
    expected_state_revisions: Mapping[str, str] | None = None
    reason_code: str = "rollback"


def _gate_fail(txn: _SqliteStoreTransaction, reason: str, **details: Any) -> None:
    raise StableError(
        code=ErrorCode.FAILED_PRECONDITION,
        message=f"promotion gate failed: {reason}",
        details=details,
    )


def promote_candidate(request: PromoteCandidateRequest):
    """Re-run the promotion gates and commit desired-only (§41.43)."""

    def mutator(txn: _SqliteStoreTransaction) -> dict[str, Any]:
        conn = txn._conn
        candidate_row = conn.execute(
            "SELECT body_json, status FROM evolution_objects"
            " WHERE object_id = ? AND realm_id = ? AND object_type = 'CANDIDATE'",
            (request.candidate_id, request.realm_id),
        ).fetchone()
        if candidate_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="candidate not found"
            )
        if candidate_row[1] != "ACTIVE":
            _gate_fail(
                txn,
                "candidate is not ACTIVE",
                status=str(candidate_row[1]),
            )
        candidate_body = _load_json(candidate_row[0])
        composition_id = str(candidate_body.get("composition_id"))
        composition = conn.execute(
            "SELECT revision, body_json FROM compositions WHERE composition_id = ?",
            (composition_id,),
        ).fetchone()
        if composition is None:
            _gate_fail(txn, "candidate composition missing")
        revision, body_json = int(composition[0]), _load_json(composition[1])

        experiment = conn.execute(
            "SELECT experiment_id FROM experiments WHERE candidate_id = ?"
            " ORDER BY created_at_us DESC, experiment_id DESC LIMIT 1",
            (request.candidate_id,),
        ).fetchone()
        if experiment is None:
            _gate_fail(txn, "candidate has no experiment")
        evaluation = conn.execute(
            "SELECT decision FROM evaluations WHERE evaluation_id = ?"
            " AND experiment_id = ?",
            (request.evaluation_id, experiment[0]),
        ).fetchone()
        if evaluation is None:
            _gate_fail(txn, "evaluation not found for candidate experiment")
        if evaluation[0] != "ACCEPT":
            _gate_fail(txn, "evaluation did not ACCEPT", decision=str(evaluation[0]))

        # Artifact gate: every candidate artifact must be resolvable VALID.
        artifact_ids = tuple(candidate_body.get("artifact_ids") or ())
        for artifact_id in artifact_ids:
            row = conn.execute(
                "SELECT integrity_status FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None or row[0] != "VALID":
                _gate_fail(
                    txn, "artifact integrity", artifact_id=str(artifact_id)
                )

        # Compatibility gate: every slot capability must be registered.
        slots = body_json.get("slots")
        if not isinstance(slots, Mapping):
            _gate_fail(txn, "candidate body has no slots")
        for name, slot_body in slots.items():
            if not isinstance(slot_body, Mapping):
                _gate_fail(txn, "slot body is not a mapping", slot=str(name))
            capability = slot_body.get("capability")
            if capability is None:
                continue
            registered = conn.execute(
                "SELECT 1 FROM capabilities WHERE capability_id = ?", (capability,)
            ).fetchone()
            if registered is None:
                _gate_fail(
                    txn,
                    "unknown capability in slot",
                    slot=str(name),
                    capability=str(capability),
                )

        # Unknown-effect gate: no unrecognized top-level declarations.
        unknown_keys = sorted(set(body_json) - _KNOWN_BODY_KEYS)
        if unknown_keys:
            _gate_fail(txn, "unknown top-level declarations", keys=unknown_keys)

        # Expected-serving gate: promotion CASes desired only from the
        # serving revision the caller observed.
        refs = _refs_row(txn, request.realm_id)
        serving = int(refs[1]) if refs is not None else 0
        if serving != request.expected_serving_revision:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="serving revision changed since observation",
                details={
                    "expected_serving_revision": str(
                        request.expected_serving_revision
                    ),
                    "serving_revision": str(serving),
                },
            )

        desired_cas = int(refs[3]) if refs is not None else 0
        desired = set_desired(
            SetDesiredRequest(
                realm_id=request.realm_id,
                revision=revision,
                expected_cas=desired_cas,
            )
        )(txn)
        from .harness import _append_fact

        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=request.candidate_id,
            event_type="promotion_requested",
            payload={
                "candidate_id": request.candidate_id,
                "evaluation_id": request.evaluation_id,
                "desired_revision": str(revision),
            },
        )
        promoted_fact = _append_fact(
            txn,
            entity_type="evolution",
            entity_id=request.candidate_id,
            event_type="candidate_promoted",
            payload={
                "desired_revision": str(revision),
                "composition_id": composition_id,
            },
        )
        return {
            "candidate_id": request.candidate_id,
            "desired_revision": revision,
            "reconcile_status": desired["reconcile_status"],
            "promotion_fact_id": promoted_fact,
        }

    return mutator


def rollback_composition(request: RollbackCompositionRequest):
    """Create a tracked desired transition back to the parent (§41.59.3)."""

    def mutator(txn: _SqliteStoreTransaction) -> dict[str, Any]:
        if request.state_strategy not in _STATE_STRATEGIES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="unknown rollback state strategy",
                details={"state_strategy": request.state_strategy},
            )
        if request.state_strategy == "RESTORE_PARENT":
            revisions = dict(request.expected_state_revisions or {})
            if not revisions:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="RESTORE_PARENT requires expected_state_revisions",
                )
            for state_id, revision_id in sorted(revisions.items()):
                known = txn._conn.execute(
                    "SELECT 1 FROM state_revisions WHERE state_revision_id = ?"
                    " AND state_id = ?",
                    (revision_id, state_id),
                ).fetchone()
                if known is None:
                    raise StableError(
                        code=ErrorCode.NOT_FOUND,
                        message="rollback state revision not found",
                        details={
                            "state_id": state_id,
                            "state_revision_id": revision_id,
                        },
                    )
        parent = txn._conn.execute(
            "SELECT revision FROM compositions WHERE composition_id = ?",
            (request.target_parent_id,),
        ).fetchone()
        if parent is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="rollback target composition not found",
                details={"composition_id": request.target_parent_id},
            )
        refs = _refs_row(txn, request.realm_id)
        serving = int(refs[1]) if refs is not None else 0
        if serving != request.expected_serving_revision:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="serving revision changed since observation",
                details={
                    "expected_serving_revision": str(
                        request.expected_serving_revision
                    ),
                    "serving_revision": str(serving),
                },
            )
        desired_cas = int(refs[3]) if refs is not None else 0
        desired = set_desired(
            SetDesiredRequest(
                realm_id=request.realm_id,
                revision=int(parent[0]),
                expected_cas=desired_cas,
            )
        )(txn)
        from .harness import _append_fact

        fact_id = _append_fact(
            txn,
            entity_type="evolution",
            entity_id=request.target_parent_id,
            event_type="promotion_requested",
            payload={
                "reason_code": request.reason_code,
                "kind": "rollback",
                "state_strategy": request.state_strategy,
                "target_parent_id": request.target_parent_id,
                "desired_revision": str(int(parent[0])),
            },
        )
        return {
            "desired_revision": int(parent[0]),
            "reconcile_status": desired["reconcile_status"],
            "state_strategy": request.state_strategy,
            "fact_id": fact_id,
        }

    return mutator
