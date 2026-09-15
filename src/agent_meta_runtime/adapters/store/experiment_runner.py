"""Deterministic candidate Experiment runner (§41.43, plan Step 08.4).

v0.1 Candidate Experiments only run the fake model against deterministic
fixtures: the baseline composition runs first on a fresh state clone,
then the candidate on ANOTHER fresh clone with the same seed; the two
runs share no live process, cache or temp file (each run body is cloned
independently and the fake model is a pure function). Any World/
placement constraint the backend does not report ``SUPPORTED`` marks the
Experiment ``INVALID`` — never degraded — and a trust class whose
placement is unavailable fails closed (``FEATURE_UNAVAILABLE``).
Evidence rows carry the deterministic run observations; the Evaluation
is produced by the pure ``deterministic-evaluation/v1`` evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable, Mapping

from ...application.evaluator import evaluate_safely
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7
from .evolution import (
    FinishExperimentRequest,
    RecordEvaluationRequest,
    RecordEvidenceRequest,
    _load_json,
    finish_experiment,
    record_evaluation,
    record_evidence,
)
from .state import StateCreateRequest, create_state
from .uow import execute_command

if TYPE_CHECKING:
    import sqlite3

    from ...domain.deadline import Deadline
    from ...domain.envelope import CommandEnvelope

__all__ = [
    "PLACEMENT_REQUIRED_FEATURES",
    "PLACEMENTS",
    "RunExperimentRequest",
    "fake_model_run",
    "run_experiment",
    "start_experiment",
    "unmet_features",
]

#: Trust class -> placement (plan Step 08.4 item 4). An untrusted
#: candidate demands Managed strong isolation.
PLACEMENTS: dict[str, str] = {
    "trusted_candidate": "PORTABLE",
    "untrusted_candidate": "MANAGED",
}

#: Features the placement requires the backend to report SUPPORTED.
PLACEMENT_REQUIRED_FEATURES: dict[str, tuple[str, ...]] = {
    "trusted_candidate": ("process", "workspace"),
    "untrusted_candidate": (
        "isolated_realm",
        "network_isolation",
        "credential_isolation",
    ),
}


def unmet_features(
    trust_class: str, backend_features: Mapping[str, str]
) -> tuple[str, ...]:
    """Features required by the placement that are not SUPPORTED."""

    required = PLACEMENT_REQUIRED_FEATURES.get(trust_class)
    if required is None:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown candidate trust class",
            details={"trust_class": trust_class},
        )
    return tuple(
        feature for feature in required if backend_features.get(feature) != "SUPPORTED"
    )


def fake_model_run(
    subject_body: Mapping[str, Any], fixtures: tuple[Mapping[str, Any], ...]
) -> dict[str, Any]:
    """Deterministic fake-model suite over composition slots.

    Each fixture names a ``slot`` and the ``expected_capability`` that
    must be wired into it; the pass rate is derived purely from the
    subject body, so the same body/fixtures/seed always produce the
    same result (AC-M42). Fixtures are applied in sorted order.
    """

    slots = subject_body.get("slots") if isinstance(subject_body, Mapping) else None
    checks: list[dict[str, Any]] = []
    for fixture in sorted(
        fixtures, key=lambda f: (str(f.get("slot")), str(f.get("expected_capability")))
    ):
        slot = str(fixture.get("slot"))
        expected = fixture.get("expected_capability")
        slot_body = slots.get(slot) if isinstance(slots, Mapping) else None
        passed = isinstance(slot_body, Mapping) and slot_body.get("capability") == expected
        checks.append(
            {
                "slot": slot,
                "expected_capability": expected,
                "passed": bool(passed),
            }
        )
    pass_count = sum(1 for check in checks if check["passed"])
    pass_rate_ppm = (1_000_000 * pass_count // len(checks)) if checks else 1_000_000
    return {
        "checks": checks,
        "pass_count": pass_count,
        "check_count": len(checks),
        "pass_rate_ppm": pass_rate_ppm,
    }


def _clone_states(
    txn: Any, body: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Clone every ``states`` binding into a NEW state_id (§41.44.1).

    Experiments must never write production state ids, so each run gets
    its own clones of the referenced Managed States (same schema and
    content artifact, fresh id) and the run body is rewritten to bind
    them. Bodies without a ``states`` mapping clone nothing.
    """

    states = body.get("states")
    if not isinstance(states, Mapping) or not states:
        return dict(body), {}
    new_body = dict(body)
    new_states: dict[str, Any] = {}
    cloned: dict[str, str] = {}
    for name in sorted(states):
        spec = states[name]
        if not isinstance(spec, Mapping) or not spec.get("state_id"):
            continue
        source = str(spec["state_id"])
        row = txn._conn.execute(
            "SELECT owner_id, schema_id, current_revision_id FROM managed_states"
            " WHERE state_id = ?",
            (source,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="bound state not found",
                details={"state_id": source},
            )
        revision = txn._conn.execute(
            "SELECT artifact_id FROM state_revisions WHERE state_revision_id = ?",
            (row[2],),
        ).fetchone()
        if revision is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="bound state revision not found",
                details={"state_revision_id": str(row[2])},
            )
        created = create_state(
            StateCreateRequest(
                owner_id=row[0], schema_id=row[1], artifact_id=revision[0]
            )
        )(txn)
        cloned[source] = created["state_id"]
        new_states[name] = {"state_id": created["state_id"]}
    new_body["states"] = new_states
    return new_body, cloned


def _artifact_integrity(txn: Any, artifact_ids: tuple[str, ...]) -> dict[str, Any]:
    """Honest integrity map: declared == observed only for VALID rows."""

    artifacts: dict[str, Any] = {}
    for artifact_id in artifact_ids:
        row = txn._conn.execute(
            "SELECT integrity_status FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        observed = "VALID" if row is not None and row[0] == "VALID" else "UNRESOLVED"
        artifacts[artifact_id] = {
            "declared_hash": "VALID",
            "observed_hash": observed,
        }
    return artifacts


def _activatable(txn: Any, body: Mapping[str, Any]) -> bool:
    slots = body.get("slots")
    if not isinstance(slots, Mapping):
        return False
    for slot_body in slots.values():
        if not isinstance(slot_body, Mapping):
            return False
        capability = slot_body.get("capability")
        if capability is None:
            continue
        row = txn._conn.execute(
            "SELECT 1 FROM capabilities WHERE capability_id = ?", (capability,)
        ).fetchone()
        if row is None:
            return False
    return True


def _seed_producer_action(txn: Any, *, actor_id: str, composition_id: str) -> str:
    action_id = "action://" + new_uuid7()
    txn._conn.execute(
        "INSERT INTO actions(action_id, task_id, actor_id, intent, composition_id,"
        " grant_id, causal_parent_action_id, status, budget_json,"
        " consumed_budget_json, created_at_us)"
        " VALUES (?, NULL, ?, 'experiment_run', ?, NULL, NULL, 'SUCCEEDED', ?, ?, ?)",
        (action_id, actor_id, composition_id, b"{}", b"{}", txn.recorded_at_us),
    )
    return action_id


@dataclass(frozen=True, slots=True)
class RunExperimentRequest:
    """Inputs the runner needs beyond what the Experiment row stores."""

    realm_id: str
    experiment_id: str
    criteria_document: Mapping[str, Any]
    evaluator_artifact_id: str
    result_artifact_id: str
    evidence_artifact_id: str
    fixtures: tuple[Mapping[str, Any], ...] = ()
    backend_features: Mapping[str, str] | None = None
    package_files: Mapping[str, bytes] | None = None
    metric_bundle: Mapping[str, Any] | None = None


def start_experiment(experiment_id: str, backend_features: Mapping[str, str]):
    """First runner phase: placement gates, state clones, RUNNING start.

    Returns ``status=INVALID`` (instead of raising) when a placement
    feature is not SUPPORTED — the Experiment must not degrade.
    """

    def mutator(txn: Any) -> dict[str, Any]:
        conn = txn._conn
        experiment = conn.execute(
            "SELECT realm_id, candidate_id, baseline_id, world_id, status"
            " FROM experiments WHERE experiment_id = ?",
            (experiment_id,),
        ).fetchone()
        if experiment is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="experiment not found"
            )
        realm_id, candidate_id, baseline_id, world_id, status = experiment
        if status != "PENDING":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="experiment is not PENDING",
                details={"status": status},
            )
        candidate = conn.execute(
            "SELECT body_json FROM evolution_objects WHERE object_id = ?"
            " AND object_type = 'CANDIDATE'",
            (candidate_id,),
        ).fetchone()
        if candidate is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="candidate not found"
            )
        candidate_object = _load_json(candidate[0])
        trust_class = str(candidate_object.get("trust_class"))
        candidate_composition_id = str(candidate_object.get("composition_id"))
        unmet = unmet_features(trust_class, backend_features)
        if unmet:
            conn.execute(
                "UPDATE experiments SET status = 'INVALID', completed_at_us = ?"
                " WHERE experiment_id = ?",
                (txn.recorded_at_us, experiment_id),
            )
            return {
                "status": "INVALID",
                "unmet_features": list(unmet),
                "placement": PLACEMENTS.get(trust_class),
            }
        world_row = conn.execute(
            "SELECT body_json FROM worlds WHERE world_id = ?", (world_id,)
        ).fetchone()
        if world_row is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="world not found")
        world = _load_json(world_row[0])
        baseline_row = conn.execute(
            "SELECT body_json FROM compositions WHERE composition_id = ?",
            (baseline_id,),
        ).fetchone()
        candidate_row = conn.execute(
            "SELECT body_json FROM compositions WHERE composition_id = ?",
            (candidate_composition_id,),
        ).fetchone()
        if baseline_row is None or candidate_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="experiment composition not found"
            )
        baseline_body, baseline_clones = _clone_states(
            txn, _load_json(baseline_row[0])
        )
        candidate_body, candidate_clones = _clone_states(
            txn, _load_json(candidate_row[0])
        )
        baseline_action_id = _seed_producer_action(
            txn,
            actor_id=txn._envelope.actor_id,
            composition_id=baseline_id,
        )
        candidate_action_id = _seed_producer_action(
            txn,
            actor_id=txn._envelope.actor_id,
            composition_id=candidate_composition_id,
        )
        conn.execute(
            "UPDATE experiments SET status = 'RUNNING' WHERE experiment_id = ?",
            (experiment_id,),
        )
        from .harness import _append_fact

        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=experiment_id,
            event_type="experiment_started",
            payload={"world_id": world_id, "seed": world.get("seed")},
        )
        return {
            "status": "RUNNING",
            "placement": PLACEMENTS[trust_class],
            "trust_class": trust_class,
            "seed": world.get("seed"),
            "baseline_id": baseline_id,
            "candidate_composition_id": candidate_composition_id,
            "baseline_body": baseline_body,
            "candidate_body": candidate_body,
            "baseline_cloned_states": baseline_clones,
            "candidate_cloned_states": candidate_clones,
            "baseline_action_id": baseline_action_id,
            "candidate_action_id": candidate_action_id,
            "baseline_artifact_integrity": {},
            "candidate_artifact_integrity": _artifact_integrity(
                txn, tuple(candidate_object.get("artifact_ids") or ())
            ),
            "baseline_activatable": _activatable(txn, baseline_body),
            "candidate_activatable": _activatable(txn, candidate_body),
        }

    return mutator


def _bundles(
    *,
    artifact_integrity: Mapping[str, Any],
    activatable: bool,
    model_result: Mapping[str, Any],
    suite_artifact_id: str | None,
) -> dict[str, Any]:
    bundles: dict[str, Any] = {
        "artifact_integrity": {"artifacts": dict(artifact_integrity)},
        "compatibility_report": {"activatable": bool(activatable)},
        # The fake model consumes no real budget: deterministic zeros.
        "budget": {"wall_time_us": 0, "cost_microunits": 0},
    }
    if suite_artifact_id is not None:
        bundles["test_suite"] = {
            "suite_artifact_id": suite_artifact_id,
            "pass_rate_ppm": model_result["pass_rate_ppm"],
        }
    return bundles


def run_experiment(
    conn: sqlite3.Connection,
    envelope: CommandEnvelope,
    request: RunExperimentRequest,
    deadline: Deadline,
    execute: Callable[..., Any] = execute_command,
) -> dict[str, Any]:
    """Run baseline (first) then candidate on separate fresh state clones.

    Pure orchestration over the store mutators: start gates -> fake-model
    runs -> evidence -> deterministic evaluation -> terminal status. The
    receipt carries the decision and the result document (with its
    ``result_hash``) so callers can persist/link artifacts.
    """

    def must(result: Any) -> Any:
        if hasattr(result, "error"):
            raise result.error
        return result.receipt

    def fresh() -> CommandEnvelope:
        # Command replay is keyed by command_id: each command in the
        # orchestration needs its own id even under one caller envelope.
        return replace(envelope, command_id=f"task://{new_uuid7()}")

    start = must(
        execute(
            conn,
            fresh(),
            start_experiment(request.experiment_id, request.backend_features or {}),
            deadline=deadline,
        )
    )
    if start["status"] == "INVALID":
        return start

    criteria = request.criteria_document
    suite_artifact_id = None
    for assertion in criteria.get("assertions", ()):
        if isinstance(assertion, Mapping) and assertion.get("kind") == "test_suite":
            suite_artifact_id = assertion.get("suite_artifact_id")
            break

    baseline_model = fake_model_run(start["baseline_body"], request.fixtures)
    candidate_model = fake_model_run(start["candidate_body"], request.fixtures)

    baseline_bundles = _bundles(
        artifact_integrity=start["baseline_artifact_integrity"],
        activatable=start["baseline_activatable"],
        model_result=baseline_model,
        suite_artifact_id=suite_artifact_id,
    )
    candidate_bundles = _bundles(
        artifact_integrity=start["candidate_artifact_integrity"],
        activatable=start["candidate_activatable"],
        model_result=candidate_model,
        suite_artifact_id=suite_artifact_id,
    )
    if request.metric_bundle is not None:
        candidate_bundles["metric"] = dict(request.metric_bundle)

    baseline_evidence = must(
        execute(
            conn,
            fresh(),
            record_evidence(
                RecordEvidenceRequest(
                    realm_id=request.realm_id,
                    experiment_id=request.experiment_id,
                    producer_action_id=start["baseline_action_id"],
                    kind="test_run",
                    subject_id=start["baseline_id"],
                    artifact_id=request.evidence_artifact_id,
                    metadata={
                        "role": "baseline",
                        "seed": start["seed"],
                        "model_result": baseline_model,
                        "cloned_states": start["baseline_cloned_states"],
                    },
                )
            ),
            deadline=deadline,
        )
    )
    candidate_evidence = must(
        execute(
            conn,
            fresh(),
            record_evidence(
                RecordEvidenceRequest(
                    realm_id=request.realm_id,
                    experiment_id=request.experiment_id,
                    producer_action_id=start["candidate_action_id"],
                    kind="test_run",
                    subject_id=start["candidate_composition_id"],
                    artifact_id=request.evidence_artifact_id,
                    metadata={
                        "role": "candidate",
                        "seed": start["seed"],
                        "model_result": candidate_model,
                        "cloned_states": start["candidate_cloned_states"],
                        "bundles": candidate_bundles,
                    },
                )
            ),
            deadline=deadline,
        )
    )

    results, decision, document = evaluate_safely(
        criteria, candidate_bundles, request.package_files or {}
    )
    if results is not None:
        assertion_rows = tuple(
            {"kind": result.kind, "status": result.status} for result in results
        )
    else:
        assertion_rows = ()

    evaluation = must(
        execute(
            conn,
            fresh(),
            record_evaluation(
                RecordEvaluationRequest(
                    realm_id=request.realm_id,
                    experiment_id=request.experiment_id,
                    evaluator_artifact_id=request.evaluator_artifact_id,
                    evidence_ids=(
                        baseline_evidence["evidence_id"],
                        candidate_evidence["evidence_id"],
                    ),
                    assertion_results=assertion_rows,
                    decision=decision,
                    result_artifact_id=request.result_artifact_id,
                )
            ),
            deadline=deadline,
        )
    )
    finished = must(
        execute(
            conn,
            fresh(),
            finish_experiment(
                FinishExperimentRequest(
                    realm_id=request.realm_id,
                    experiment_id=request.experiment_id,
                    status="COMPLETED",
                )
            ),
            deadline=deadline,
        )
    )
    return {
        "status": finished["status"],
        "decision": decision,
        "evaluation_id": evaluation["evaluation_id"],
        "evidence_ids": [
            baseline_evidence["evidence_id"],
            candidate_evidence["evidence_id"],
        ],
        "result_document": document,
        "candidate_model_result": candidate_model,
        "baseline_model_result": baseline_model,
    }
