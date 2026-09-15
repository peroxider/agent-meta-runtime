"""Canonical Fact catalog and causal edge registry (§41.35, FR-MFACT-005).

Adapters may not invent event types: v0.1 event types are fixed per entity and
every new type must first enter this registry. Payload schemas require
``schema_version=1``; transition-class events additionally carry a
``reason_code`` plus the old/new status. Causal edges use only the ten
registered edge types with a fixed subject→target direction.
"""

from __future__ import annotations

from .errors import ErrorCode, StableError

__all__ = [
    "CAUSAL_EDGE_TYPES",
    "ENTITY_EVENT_TYPES",
    "ENTITY_ID_SCHEMES",
    "LINEAGE_EDGE_TYPES",
    "TRANSITION_EVENTS",
    "WHY_EDGE_TYPES",
    "validate_causal_edge",
    "validate_fact_event",
]

ENTITY_EVENT_TYPES: dict[str, frozenset[str]] = {
    "runtime": frozenset(
        {
            "runtime_initialized",
            "runtime_started",
            "runtime_stopping",
            "readiness_changed",
            "epoch_created",
        }
    ),
    "artifact": frozenset(
        {
            "artifact_registered",
            "artifact_verified",
            "artifact_corrupt_observed",
            "artifact_accessed_restricted",
            "artifact_crypto_erased",
        }
    ),
    "capability": frozenset(
        {
            "capability_defined",
            "capability_validated",
            "instance_transitioned",
            "instance_degraded",
        }
    ),
    "harness": frozenset(
        {
            "harness_installed",
            "harness_activated",
            "harness_deactivated",
            "harness_uninstalled",
            "harness_contract_rejected",
        }
    ),
    "composition": frozenset(
        {
            "composition_committed",
            "reconcile_started",
            "serving_switched",
            "realization_completed",
            "reconcile_failed",
            "composition_rolled_back",
        }
    ),
    "state": frozenset(
        {
            "state_revision_created",
            "migration_started",
            "migration_completed",
            "migration_failed",
        }
    ),
    "authority": frozenset(
        {
            "grant_created",
            "grant_delegated",
            "grant_revoked",
            "authority_denied",
            "root_recovery_performed",
        }
    ),
    "task": frozenset(
        {
            "task_accepted",
            "task_started",
            "task_succeeded",
            "task_failed",
            "task_recovery_failed",
            "task_cancel_requested",
            "task_cancelled",
            "task_timed_out",
        }
    ),
    "action": frozenset(
        {"action_started", "action_finished", "late_completion_observed"}
    ),
    "invocation": frozenset(
        {
            "invocation_created",
            "invocation_attempted",
            "invocation_finished",
            "late_completion_observed",
        }
    ),
    "execution": frozenset(
        {
            "execution_submitted",
            "execution_bound",
            "execution_status_observed",
            "execution_orphan_quarantined",
            "external_effect_unknown",
            "terminal_acknowledged",
        }
    ),
    "evolution": frozenset(
        {
            "proposal_created",
            "candidate_created",
            "experiment_started",
            "evidence_recorded",
            "evaluation_recorded",
            "promotion_requested",
            "candidate_promoted",
            "candidate_rejected",
        }
    ),
    "operations": frozenset(
        {
            "outbox_dead_lettered",
            "projection_rebuilt",
            "security_degradation_observed",
            "diagnostics_collected",
            "backup_created",
            "backup_snapshot_restored",
            "artifact_gc_quarantined",
            "gc_plan_recorded",
            "runtime_upgraded",
        }
    ),
}

EVENT_ENTITY: dict[str, str] = {
    event: entity for entity, events in ENTITY_EVENT_TYPES.items() for event in events
}

# Transition-class events must record reason_code plus old/new status in their
# payload; other state-change events record reason_code only.
TRANSITION_EVENTS: frozenset[str] = frozenset(
    {
        "readiness_changed",
        "instance_transitioned",
        "instance_degraded",
        "serving_switched",
        "task_started",
        "task_succeeded",
        "task_failed",
        "task_recovery_failed",
        "task_cancelled",
        "task_timed_out",
        "action_started",
        "action_finished",
        "invocation_finished",
        "grant_revoked",
    }
)

REASON_CODE_EVENTS: frozenset[str] = TRANSITION_EVENTS | frozenset(
    {
        "runtime_stopping",
        "artifact_corrupt_observed",
        "harness_contract_rejected",
        "reconcile_failed",
        "migration_failed",
        "authority_denied",
        "task_cancel_requested",
        "late_completion_observed",
        "execution_orphan_quarantined",
        "external_effect_unknown",
        "candidate_rejected",
        "outbox_dead_lettered",
        "security_degradation_observed",
    }
)

# Registry entity → allowed id-scheme prefixes for causal edge validation.
ENTITY_ID_SCHEMES: dict[str, frozenset[str]] = {
    "runtime": frozenset({"realm", "epoch"}),
    "artifact": frozenset({"artifact"}),
    "capability": frozenset({"capability"}),
    "composition": frozenset({"composition"}),
    "state": frozenset({"state", "state-revision"}),
    "authority": frozenset({"grant"}),
    "task": frozenset({"task"}),
    "action": frozenset({"action"}),
    "invocation": frozenset({"invocation"}),
    "execution": frozenset({"instance", "workspace"}),
    "evolution": frozenset(
        {
            "proposal",
            "change-set",
            "candidate",
            "world",
            "experiment",
            "evidence",
            "evaluation",
        }
    ),
    "operations": frozenset({"operation"}),
}

_CAUSAL_EDGE_DIRECTIONS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # edge_type: (allowed from schemes, allowed to schemes)
    "caused_by": (
        frozenset(
            ENTITY_ID_SCHEMES["runtime"]
            | ENTITY_ID_SCHEMES["artifact"]
            | ENTITY_ID_SCHEMES["capability"]
            | ENTITY_ID_SCHEMES["composition"]
            | ENTITY_ID_SCHEMES["state"]
            | ENTITY_ID_SCHEMES["task"]
            | ENTITY_ID_SCHEMES["action"]
            | ENTITY_ID_SCHEMES["invocation"]
        ),
        frozenset({"action"}),
    ),
    "part_of": (frozenset({"invocation", "action"}), frozenset({"task", "action"})),
    "used": (
        frozenset({"action", "evaluation"}),
        frozenset({"artifact", "state", "state-revision", "evidence"}),
    ),
    "produced": (
        frozenset({"action", "invocation"}),
        frozenset({"artifact", "evidence"}),
    ),
    "authorized_by": (frozenset({"action"}), frozenset({"grant"})),
    "derived_from": (
        frozenset({"artifact", "state", "state-revision", "evidence"}),
        frozenset({"artifact", "state", "state-revision", "evidence"}),
    ),
    "evaluated_by": (frozenset({"experiment", "evidence"}), frozenset({"evaluation"})),
    "promoted_to": (frozenset({"candidate"}), frozenset({"composition"})),
    "executed_as": (
        frozenset({"action", "invocation"}),
        frozenset({"instance", "workspace"}),
    ),
    "supersedes": (
        frozenset({"state-revision", "fact"}),
        frozenset({"state-revision", "fact"}),
    ),
}

CAUSAL_EDGE_TYPES: frozenset[str] = frozenset(_CAUSAL_EDGE_DIRECTIONS)

WHY_EDGE_TYPES: frozenset[str] = frozenset(
    {"caused_by", "part_of", "authorized_by", "used", "derived_from", "executed_as"}
)
LINEAGE_EDGE_TYPES: frozenset[str] = frozenset(
    {"produced", "derived_from", "evaluated_by", "promoted_to", "supersedes"}
)


def _scheme_of(entity_id: str) -> str:
    return entity_id.split("://", 1)[0]


def validate_fact_event(
    entity_type: str,
    event_type: str,
    schema_version: int,
    payload: dict,
) -> None:
    """Validate a Fact against the v0.1 catalog (§41.35)."""

    events = ENTITY_EVENT_TYPES.get(entity_type)
    if events is None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown fact entity_type",
            details={"entity_type": entity_type},
        )
    if event_type not in events:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="event_type not in registry for entity",
            details={"entity_type": entity_type, "event_type": event_type},
        )
    if schema_version != 1:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="fact schema_version must be 1 in v0.1",
            details={"event_type": event_type, "schema_version": str(schema_version)},
        )
    if event_type in REASON_CODE_EVENTS and not isinstance(
        payload.get("reason_code"), str
    ):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="state-change fact payload requires reason_code",
            details={"event_type": event_type},
        )
    if event_type in TRANSITION_EVENTS and not (
        isinstance(payload.get("old_status"), str)
        and isinstance(payload.get("new_status"), str)
    ):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="transition fact payload requires old_status and new_status",
            details={"event_type": event_type},
        )


def validate_causal_edge(edge_type: str, from_id: str, to_id: str) -> None:
    """Validate edge type and fixed subject→target direction (§41.35)."""

    direction = _CAUSAL_EDGE_DIRECTIONS.get(edge_type)
    if direction is None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown causal edge type",
            details={"edge_type": edge_type},
        )
    allowed_from, allowed_to = direction
    from_scheme, to_scheme = _scheme_of(from_id), _scheme_of(to_id)
    if from_scheme not in allowed_from or to_scheme not in allowed_to:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="causal edge direction violates registry",
            details={
                "edge_type": edge_type,
                "from_scheme": from_scheme,
                "to_scheme": to_scheme,
            },
        )
