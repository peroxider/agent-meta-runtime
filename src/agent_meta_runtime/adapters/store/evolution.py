"""Evolution v0 baseline store use cases (§41.43, FR-MEVO-001..006).

Proposals, ChangeSets and Candidates live in ``evolution_objects`` as
immutable JCS bodies; applying a ChangeSet materializes a NEW composition
revision (the baseline is never modified). Worlds, Experiments, Evidence
and Evaluations use their dedicated tables — Evidence rows are append-only
by trigger and an Evaluation never rewrites old Evidence (FR-MEVO-002).
Evaluator crashes are recorded as ``decision=REJECT`` with
``status=FAILED`` in the body: a FAILED Evaluation must never be readable
as ACCEPT (FR-MEVO-006) and the CHECK constraint only admits ACCEPT/
REJECT.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.evolution import (
    CANDIDATE_TRUST_CLASSES,
    ChangeSet,
    ChangeSetOperation,
    apply_change_set,
    validate_change_set,
)
from ...domain.ids import new_uuid7
from ...domain.semantics import TaskBudget
from .composition import CompositionCreateRequest, create_composition
from .harness import _append_fact

if TYPE_CHECKING:
    import sqlite3

    from .uow import _SqliteStoreTransaction

__all__ = [
    "ArchiveCandidateRequest",
    "CreateChangeSetRequest",
    "CreateExperimentRequest",
    "CreateWorldRequest",
    "FinishExperimentRequest",
    "RecordEvaluationRequest",
    "RecordEvidenceRequest",
    "RegisterCandidateRequest",
    "SubmitProposalRequest",
    "archive_candidate",
    "create_change_set",
    "create_experiment",
    "create_world",
    "finish_experiment",
    "get_evolution_object",
    "get_experiment_row",
    "list_evolution_objects",
    "list_experiments",
    "list_worlds",
    "record_evaluation",
    "record_evidence",
    "register_candidate",
    "submit_proposal",
]

_OBJECT_TYPES = frozenset({"PROPOSAL", "CHANGE_SET", "CANDIDATE"})


def _require(conn: sqlite3.Connection, sql: str, params: tuple, message: str) -> Any:
    row = conn.execute(sql, params).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message=message)
    return row


def _load_json(blob: Any) -> Any:
    return json.loads(bytes(blob).decode("utf-8"))


# ------------------------------------------------------------- requests --


@dataclass(frozen=True, slots=True)
class SubmitProposalRequest:
    realm_id: str
    hypothesis: str
    source_evidence_ids: tuple[str, ...]
    target_composition_id: str


@dataclass(frozen=True, slots=True)
class CreateChangeSetRequest:
    realm_id: str
    proposal_id: str
    baseline_id: str
    operations: tuple[Mapping[str, Any], ...]
    expected_serving_revision: int


@dataclass(frozen=True, slots=True)
class RegisterCandidateRequest:
    realm_id: str
    change_set_id: str
    trust_class: str
    artifact_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CreateWorldRequest:
    realm_id: str
    backend_profile_hash: str
    fixture_artifact_ids: tuple[str, ...]
    state_snapshot_ids: tuple[str, ...]
    environment_allowlist: tuple[str, ...]
    workspace_quota: Mapping[str, int]
    budget: TaskBudget
    seed: int
    replay_level: str


@dataclass(frozen=True, slots=True)
class CreateExperimentRequest:
    realm_id: str
    candidate_id: str
    baseline_id: str
    world_id: str
    criteria_artifact_id: str
    budget: TaskBudget


@dataclass(frozen=True, slots=True)
class RecordEvidenceRequest:
    realm_id: str
    experiment_id: str | None
    producer_action_id: str
    kind: str
    subject_id: str
    artifact_id: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class RecordEvaluationRequest:
    realm_id: str
    experiment_id: str
    evaluator_artifact_id: str
    evidence_ids: tuple[str, ...]
    assertion_results: tuple[Mapping[str, Any], ...]
    decision: str  # ACCEPT | REJECT | FAILED
    result_artifact_id: str


@dataclass(frozen=True, slots=True)
class ArchiveCandidateRequest:
    realm_id: str
    candidate_id: str


@dataclass(frozen=True, slots=True)
class FinishExperimentRequest:
    realm_id: str
    experiment_id: str
    status: str  # COMPLETED | FAILED


# ------------------------------------------------------------- mutators --


def submit_proposal(request: SubmitProposalRequest):
    """Record one Proposal (FR-MEVO-001: separated from Experiment/Evidence)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _require(
            txn._conn,
            "SELECT 1 FROM compositions WHERE composition_id = ? AND realm_id = ?",
            (request.target_composition_id, request.realm_id),
            "target composition not found",
        )
        proposal_id = "proposal://" + new_uuid7()
        body = {
            "hypothesis": request.hypothesis,
            "source_evidence_ids": list(request.source_evidence_ids),
            "target_composition_id": request.target_composition_id,
        }
        txn._conn.execute(
            "INSERT INTO evolution_objects(object_id, realm_id, object_type,"
            " parent_id, body_json, status, created_by, created_at_us)"
            " VALUES (?, ?, 'PROPOSAL', NULL, ?, 'OPEN', ?, ?)",
            (
                proposal_id,
                request.realm_id,
                canonical_json(body),
                txn._envelope.actor_id,
                txn.recorded_at_us,
            ),
        )
        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=proposal_id,
            event_type="proposal_created",
            payload={
                "target_composition_id": request.target_composition_id,
                "hypothesis": request.hypothesis,
            },
        )
        return {"proposal_id": proposal_id}

    return mutator


def create_change_set(request: CreateChangeSetRequest):
    """Validate and persist one typed ChangeSet (§41.43 tagged union)."""

    operations = tuple(
        ChangeSetOperation(
            operation=dict(op)["operation"],
            target_path=dict(op)["target_path"],
            expected_old_value_hash=dict(op).get("expected_old_value_hash"),
            new_value=dict(op).get("new_value"),
        )
        for op in request.operations
    )
    change_set = ChangeSet(
        change_set_id="change-set://" + new_uuid7(),
        proposal_id=request.proposal_id,
        baseline_id=request.baseline_id,
        operations=operations,
        expected_serving_revision=request.expected_serving_revision,
    )
    issues = validate_change_set(change_set)
    if issues:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="change set is not well-formed",
            details={"issues": list(issues)},
        )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _require(
            txn._conn,
            "SELECT 1 FROM evolution_objects WHERE object_id = ? AND realm_id = ?"
            " AND object_type = 'PROPOSAL'",
            (request.proposal_id, request.realm_id),
            "proposal not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM compositions WHERE composition_id = ? AND realm_id = ?",
            (request.baseline_id, request.realm_id),
            "baseline composition not found",
        )
        body = {
            "proposal_id": request.proposal_id,
            "baseline_id": request.baseline_id,
            "operations": [
                {
                    "operation": op.operation,
                    "target_path": op.target_path,
                    "expected_old_value_hash": op.expected_old_value_hash,
                    "new_value": op.new_value,
                }
                for op in operations
            ],
            "expected_serving_revision": request.expected_serving_revision,
        }
        txn._conn.execute(
            "INSERT INTO evolution_objects(object_id, realm_id, object_type,"
            " parent_id, body_json, status, created_by, created_at_us)"
            " VALUES (?, ?, 'CHANGE_SET', ?, ?, 'OPEN', ?, ?)",
            (
                change_set.change_set_id,
                request.realm_id,
                request.proposal_id,
                canonical_json(body),
                txn._envelope.actor_id,
                txn.recorded_at_us,
            ),
        )
        return {"change_set_id": change_set.change_set_id}

    return mutator


def register_candidate(request: RegisterCandidateRequest):
    """Apply the ChangeSet and materialize the candidate Composition.

    The ChangeSet generates a NEW composition revision; the baseline row
    is untouched (§41.43). The candidate references that revision and the
    given trust class.
    """

    if request.trust_class not in CANDIDATE_TRUST_CLASSES:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown candidate trust class",
            details={"trust_class": request.trust_class},
        )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        change_set_row = _require(
            txn._conn,
            "SELECT object_id, parent_id, body_json FROM evolution_objects"
            " WHERE object_id = ? AND realm_id = ? AND object_type = 'CHANGE_SET'",
            (request.change_set_id, request.realm_id),
            "change set not found",
        )
        cs_body = _load_json(change_set_row[2])
        baseline_row = _require(
            txn._conn,
            "SELECT body_json FROM compositions WHERE composition_id = ? AND realm_id = ?",
            (cs_body["baseline_id"], request.realm_id),
            "baseline composition not found",
        )
        change_set = ChangeSet(
            change_set_id=change_set_row[0],
            proposal_id=cs_body["proposal_id"],
            baseline_id=cs_body["baseline_id"],
            operations=tuple(
                ChangeSetOperation(
                    operation=dict(op)["operation"],
                    target_path=dict(op)["target_path"],
                    expected_old_value_hash=dict(op).get("expected_old_value_hash"),
                    new_value=dict(op).get("new_value"),
                )
                for op in cs_body["operations"]
            ),
            expected_serving_revision=cs_body["expected_serving_revision"],
        )
        candidate_body = apply_change_set(_load_json(baseline_row[0]), change_set)
        next_revision = int(
            txn._conn.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM compositions WHERE realm_id = ?",
                (request.realm_id,),
            ).fetchone()[0]
        )
        created = create_composition(
            CompositionCreateRequest(
                realm_id=request.realm_id,
                body=candidate_body,
                created_by=txn._envelope.actor_id,
                revision=next_revision,
                parent_id=cs_body["baseline_id"],
            )
        )(txn)
        candidate_id = "candidate://" + new_uuid7()
        body = {
            "change_set_id": request.change_set_id,
            "composition_id": created["composition_id"],
            "trust_class": request.trust_class,
            "artifact_ids": list(request.artifact_ids),
        }
        txn._conn.execute(
            "INSERT INTO evolution_objects(object_id, realm_id, object_type,"
            " parent_id, body_json, status, created_by, created_at_us)"
            " VALUES (?, ?, 'CANDIDATE', ?, ?, 'ACTIVE', ?, ?)",
            (
                candidate_id,
                request.realm_id,
                request.change_set_id,
                canonical_json(body),
                txn._envelope.actor_id,
                txn.recorded_at_us,
            ),
        )
        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=candidate_id,
            event_type="candidate_created",
            payload={
                "change_set_id": request.change_set_id,
                "composition_id": created["composition_id"],
                "trust_class": request.trust_class,
            },
        )
        return {
            "candidate_id": candidate_id,
            "composition_id": created["composition_id"],
            "revision": created["revision"],
        }

    return mutator


def create_world(request: CreateWorldRequest):
    """Persist one frozen World v1 (network DENY, no credential handles)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        world_id = "world://" + new_uuid7()
        body = {
            "backend_profile_hash": request.backend_profile_hash,
            "fixture_artifact_ids": list(request.fixture_artifact_ids),
            "state_snapshot_ids": list(request.state_snapshot_ids),
            "environment_allowlist": list(request.environment_allowlist),
            "network_policy": "DENY",
            "credential_handles": [],
            "workspace_quota": dict(request.workspace_quota),
            "budget": {
                "max_turns": request.budget.max_turns,
                "max_steps": request.budget.max_steps,
                "max_model_calls": request.budget.max_model_calls,
            },
            "seed": request.seed,
            "replay_level": request.replay_level,
        }
        body_json = canonical_json(body)
        txn._conn.execute(
            "INSERT INTO worlds(world_id, realm_id, backend_profile_hash,"
            " body_json, body_hash, created_at_us) VALUES (?, ?, ?, ?, ?, ?)",
            (
                world_id,
                request.realm_id,
                request.backend_profile_hash,
                body_json,
                sha256_hex(body_json),
                txn.recorded_at_us,
            ),
        )
        return {"world_id": world_id}

    return mutator


def create_experiment(request: CreateExperimentRequest):
    """Open one Experiment; status stays PENDING until the runner starts it."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _require(
            txn._conn,
            "SELECT 1 FROM evolution_objects WHERE object_id = ? AND realm_id = ?"
            " AND object_type = 'CANDIDATE'",
            (request.candidate_id, request.realm_id),
            "candidate not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM compositions WHERE composition_id = ? AND realm_id = ?",
            (request.baseline_id, request.realm_id),
            "baseline composition not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM worlds WHERE world_id = ? AND realm_id = ?",
            (request.world_id, request.realm_id),
            "world not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM artifacts WHERE artifact_id = ?",
            (request.criteria_artifact_id,),
            "criteria artifact not found",
        )
        experiment_id = "experiment://" + new_uuid7()
        budget_body = {
            "max_turns": request.budget.max_turns,
            "max_steps": request.budget.max_steps,
            "max_model_calls": request.budget.max_model_calls,
        }
        body = {
            "baseline_id": request.baseline_id,
            "criteria_artifact_id": request.criteria_artifact_id,
            "budget": budget_body,
        }
        txn._conn.execute(
            "INSERT INTO experiments(experiment_id, realm_id, candidate_id,"
            " baseline_id, world_id, criteria_artifact_id, budget_json, status,"
            " body_json, created_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)",
            (
                experiment_id,
                request.realm_id,
                request.candidate_id,
                request.baseline_id,
                request.world_id,
                request.criteria_artifact_id,
                canonical_json(budget_body),
                canonical_json(body),
                txn.recorded_at_us,
            ),
        )
        return {"experiment_id": experiment_id}

    return mutator


def record_evidence(request: RecordEvidenceRequest):
    """Append one immutable Evidence row + fact (FR-MEVO-002)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _require(
            txn._conn,
            "SELECT 1 FROM actions WHERE action_id = ?",
            (request.producer_action_id,),
            "producer action not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM artifacts WHERE artifact_id = ?",
            (request.artifact_id,),
            "evidence artifact not found",
        )
        if request.experiment_id is not None:
            _require(
                txn._conn,
                "SELECT 1 FROM experiments WHERE experiment_id = ? AND realm_id = ?",
                (request.experiment_id, request.realm_id),
                "experiment not found",
            )
        evidence_id = "evidence://" + new_uuid7()
        txn._conn.execute(
            "INSERT INTO evidence(evidence_id, experiment_id, producer_action_id,"
            " kind, subject_id, artifact_id, world_id, observed_at_us, metadata_json)"
            " VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            (
                evidence_id,
                request.experiment_id,
                request.producer_action_id,
                request.kind,
                request.subject_id,
                request.artifact_id,
                txn.recorded_at_us,
                canonical_json(dict(request.metadata)),
            ),
        )
        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=evidence_id,
            event_type="evidence_recorded",
            payload={
                "kind": request.kind,
                "subject_id": request.subject_id,
                "artifact_id": request.artifact_id,
            },
        )
        return {"evidence_id": evidence_id}

    return mutator


def record_evaluation(request: RecordEvaluationRequest):
    """Commit one Evaluation against frozen Evidence (§41.43, FR-MEVO-006).

    ``decision=FAILED`` (evaluator crash) is stored as REJECT with
    ``status=FAILED`` — never as ACCEPT — because the store CHECK only
    admits ACCEPT/REJECT and a FAILED Evaluation must be safe-side.
    """

    if request.decision not in ("ACCEPT", "REJECT", "FAILED"):
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown evaluation decision",
            details={"decision": request.decision},
        )

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        _require(
            txn._conn,
            "SELECT 1 FROM experiments WHERE experiment_id = ? AND realm_id = ?",
            (request.experiment_id, request.realm_id),
            "experiment not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM artifacts WHERE artifact_id = ?",
            (request.evaluator_artifact_id,),
            "evaluator artifact not found",
        )
        _require(
            txn._conn,
            "SELECT 1 FROM artifacts WHERE artifact_id = ?",
            (request.result_artifact_id,),
            "evaluation result artifact not found",
        )
        if request.evidence_ids:
            placeholders = ",".join("?" for _ in request.evidence_ids)
            found = {
                row[0]
                for row in txn._conn.execute(
                    f"SELECT evidence_id FROM evidence WHERE evidence_id IN ({placeholders})",
                    tuple(request.evidence_ids),
                ).fetchall()
            }
            missing = sorted(set(request.evidence_ids) - found)
            if missing:
                raise StableError(
                    code=ErrorCode.NOT_FOUND,
                    message="evaluation references unknown evidence",
                    details={"missing_evidence_ids": missing},
                )
        decision = "REJECT" if request.decision == "FAILED" else request.decision
        evaluation_id = "evaluation://" + new_uuid7()
        body = {
            "status": "FAILED" if request.decision == "FAILED" else "COMPLETED",
            "assertion_results": [dict(r) for r in request.assertion_results],
        }
        txn._conn.execute(
            "INSERT INTO evaluations(evaluation_id, experiment_id,"
            " evaluator_artifact_id, evidence_ids_json, result_artifact_id,"
            " decision, created_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                evaluation_id,
                request.experiment_id,
                request.evaluator_artifact_id,
                canonical_json(list(request.evidence_ids)),
                request.result_artifact_id,
                decision,
                txn.recorded_at_us,
            ),
        )
        _append_fact(
            txn,
            entity_type="evolution",
            entity_id=evaluation_id,
            event_type="evaluation_recorded",
            payload={
                "experiment_id": request.experiment_id,
                "decision": decision,
                "status": body["status"],
            },
        )
        if decision == "REJECT":
            row = txn._conn.execute(
                "SELECT candidate_id FROM experiments WHERE experiment_id = ?",
                (request.experiment_id,),
            ).fetchone()
            if row is not None:
                _append_fact(
                    txn,
                    entity_type="evolution",
                    entity_id=row[0],
                    event_type="candidate_rejected",
                    payload={
                        "reason_code": "EVALUATION_REJECTED",
                        "evaluation_id": evaluation_id,
                    },
                )
        return {"evaluation_id": evaluation_id, "decision": decision}

    return mutator


def finish_experiment(request: FinishExperimentRequest):
    """Terminal transition RUNNING -> COMPLETED/FAILED (status only)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        if request.status not in ("COMPLETED", "FAILED"):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="terminal experiment status must be COMPLETED or FAILED",
                details={"status": request.status},
            )
        row = txn._conn.execute(
            "SELECT status FROM experiments WHERE experiment_id = ? AND realm_id = ?",
            (request.experiment_id, request.realm_id),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="experiment not found"
            )
        if row[0] != "RUNNING":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="only a RUNNING experiment can finish",
                details={"status": row[0]},
            )
        txn._conn.execute(
            "UPDATE experiments SET status = ?, completed_at_us = ?"
            " WHERE experiment_id = ?",
            (request.status, txn.recorded_at_us, request.experiment_id),
        )
        return {"experiment_id": request.experiment_id, "status": request.status}

    return mutator


def archive_candidate(request: ArchiveCandidateRequest):
    """Candidate archive is a status change; nothing is deleted (FR-MEVO-005)."""

    def mutator(txn: "_SqliteStoreTransaction") -> dict[str, Any]:
        row = _require(
            txn._conn,
            "SELECT status FROM evolution_objects WHERE object_id = ?"
            " AND realm_id = ? AND object_type = 'CANDIDATE'",
            (request.candidate_id, request.realm_id),
            "candidate not found",
        )
        if row[0] != "ARCHIVED":
            txn._conn.execute(
                "UPDATE evolution_objects SET status = 'ARCHIVED' WHERE object_id = ?",
                (request.candidate_id,),
            )
        return {"candidate_id": request.candidate_id, "status": "ARCHIVED"}

    return mutator


# -------------------------------------------------------------- queries --


def _object_dict(row: tuple) -> dict[str, Any]:
    return {
        "object_id": row[0],
        "realm_id": row[1],
        "object_type": row[2],
        "parent_id": row[3],
        "body": _load_json(row[4]),
        "status": row[5],
        "created_by": row[6],
        "created_at_us": row[7],
    }


_OBJECT_COLUMNS = (
    "SELECT object_id, realm_id, object_type, parent_id, body_json, status,"
    " created_by, created_at_us FROM evolution_objects"
)


def get_evolution_object(conn: sqlite3.Connection, object_id: str) -> dict[str, Any]:
    row = _require(
        conn,
        _OBJECT_COLUMNS + " WHERE object_id = ?",
        (object_id,),
        "evolution object not found",
    )
    return _object_dict(row)


def list_evolution_objects(
    conn: sqlite3.Connection, realm_id: str, object_type: str | None = None
) -> list[dict[str, Any]]:
    if object_type is not None and object_type not in _OBJECT_TYPES:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="unknown evolution object type",
        )
    if object_type is None:
        rows = conn.execute(
            _OBJECT_COLUMNS + " WHERE realm_id = ? ORDER BY created_at_us, object_id",
            (realm_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            _OBJECT_COLUMNS
            + " WHERE realm_id = ? AND object_type = ? ORDER BY created_at_us, object_id",
            (realm_id, object_type),
        ).fetchall()
    return [_object_dict(row) for row in rows]


def _experiment_dict(row: tuple) -> dict[str, Any]:
    return {
        "experiment_id": row[0],
        "realm_id": row[1],
        "candidate_id": row[2],
        "baseline_id": row[3],
        "world_id": row[4],
        "criteria_artifact_id": row[5],
        "status": row[6],
        "body": _load_json(row[7]),
        "created_at_us": row[8],
        "completed_at_us": row[9],
    }


_EXPERIMENT_COLUMNS = (
    "SELECT experiment_id, realm_id, candidate_id, baseline_id, world_id,"
    " criteria_artifact_id, status, body_json, created_at_us, completed_at_us"
    " FROM experiments"
)


def get_experiment_row(conn: sqlite3.Connection, experiment_id: str) -> dict[str, Any]:
    row = _require(
        conn,
        _EXPERIMENT_COLUMNS + " WHERE experiment_id = ?",
        (experiment_id,),
        "experiment not found",
    )
    return _experiment_dict(row)


def list_experiments(conn: sqlite3.Connection, realm_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        _EXPERIMENT_COLUMNS + " WHERE realm_id = ? ORDER BY created_at_us, experiment_id",
        (realm_id,),
    ).fetchall()
    return [_experiment_dict(row) for row in rows]


def list_worlds(conn: sqlite3.Connection, realm_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT world_id, realm_id, backend_profile_hash, body_json, body_hash,"
        " created_at_us FROM worlds WHERE realm_id = ? ORDER BY created_at_us, world_id",
        (realm_id,),
    ).fetchall()
    return [
        {
            "world_id": row[0],
            "realm_id": row[1],
            "backend_profile_hash": row[2],
            "body": _load_json(row[3]),
            "body_hash": row[4],
            "created_at_us": row[5],
        }
        for row in rows
    ]
