"""Public API method handlers (§41.26, §41.46, §41.51, §41.52).

Every handler receives the parsed protobuf request and the request
deadline (absolute µs) and returns the protobuf response. Read handlers
answer from the Meta Store views/doctor/readiness evaluator; write
handlers parse the canonical ``CommandEnvelope`` JCS carried in
``CommandRequest`` and dispatch through ``execute_command`` — the CLI/SDK
never writes the store directly (§41.26). Mutating responses carry the
``MutationReceipt`` (command_id/action_id/meta_revision) JCS plus the
created resource JCS (FR-MAPI-001/002). ``Task.Submit`` is only admitted
while ``serving_ready`` (§41.52); ``RuntimeInfo.ready`` is hard-bound to
``core_ready``. Evolution RPCs are fail-closed placeholders until their
implementing slice lands.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Mapping

from ...adapters.cas import FilesystemCas
from ...adapters.execution_portable.backend import PORTABLE_FEATURES
from ...adapters.store.backup import create_backup
from ...adapters.store.gc import (
    apply_gc_quarantine,
    build_gc_plan,
    commit_gc_plan,
    move_quarantined_to_trash,
    validate_gc_plan,
)
from ...adapters.store.operations import (
    BeginOperationRequest,
    FinishOperationRequest,
    begin_operation,
    finish_operation,
    get_operation_row,
)
from ...adapters.store import (
    CompositionCreateRequest,
    TaskAcceptRequest,
    accept_task,
    create_composition,
    execute_command,
    get_current_view,
    get_historical_view,
    load_task,
    request_task_cancel,
)
from ...adapters.store.evolution import (
    CreateExperimentRequest,
    SubmitProposalRequest,
    create_experiment,
    get_experiment_row,
    submit_proposal,
)
from ...adapters.store.experiment_runner import (
    RunExperimentRequest,
    run_experiment,
)
from ...adapters.store.harness import (
    ActivateHarnessRequest,
    DeactivateHarnessRequest,
    InstallHarnessRequest,
    ScopedGrantSpec,
    UninstallHarnessRequest,
    activate_harness,
    deactivate_harness,
    get_harness_row,
    install_harness,
    list_harness_rows,
    uninstall_harness,
)
from ...adapters.store.causal import SqliteEdgeSource
from ...adapters.store.doctor import run_integrity_doctor
from ...adapters.store.promotion import (
    PromoteCandidateRequest,
    RollbackCompositionRequest,
    promote_candidate,
    rollback_composition,
)
from ...domain.evolution import validate_criteria
from ...adapters.store.uow import Deadline
from ...domain.canonical import canonical_json
from ...domain.causal_query import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_NODES,
    lineage as lineage_query,
)
from ...domain.causal_query import why as why_query
from ...domain.envelope import CommandEnvelope
from ...domain.errors import ErrorCode, StableError
from ...domain.authority import ScopeTarget
from ...domain.harness import validate_manifest
from ...domain.semantics import TaskBudget, TaskStatus
from ...protocols._v1 import public_pb2 as pub
from .staging import ChunkedStaging

__all__ = ["PublicApiHandlers"]

_TERMINAL_TASK_STATUSES = frozenset(
    {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.TIMED_OUT, TaskStatus.CANCELLED}
)

_TERMINAL_EXPERIMENT_STATUSES = frozenset({"COMPLETED", "FAILED", "INVALID"})


def _resource(resource_type: str, fields: Mapping[str, Any]) -> bytes:
    body = dict(fields)
    body["resource_type"] = resource_type
    body["schema_version"] = 1
    return canonical_json(body)


def _sleep_s(seconds: float) -> None:
    import time

    time.sleep(seconds)


def _append_backup_fact(
    txn, *, operation_id: str, payload: Mapping[str, Any]
) -> str:
    from ...adapters.store.harness import _append_fact as _store_append_fact

    return _store_append_fact(
        txn,
        entity_type="operations",
        entity_id=operation_id,
        event_type="backup_created",
        payload={
            "destination": payload["destination"],
            "manifest_sha256": payload["manifest_sha256"],
            "meta_revision": payload["meta_revision"],
        },
    )


class PublicApiHandlers:
    """Concrete handler set bound to one open store connection."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        data_dir: Path,
        realm_id: str,
        db_path: Path,
        cas: FilesystemCas,
        staging: ChunkedStaging,
        readiness: Callable[[], Any],
        command_deadline_us: int = 5_000_000,
        now_us: Callable[[], int],
    ) -> None:
        self._conn = conn
        self._data_dir = Path(data_dir)
        self._realm_id = realm_id
        self._db_path = Path(db_path)
        self._cas = cas
        self._staging = staging
        self._readiness = readiness
        self._deadline_us = command_deadline_us
        self._now_us = now_us

    # -- registry ----------------------------------------------------------
    def handlers(self) -> dict[str, Callable[[Any, int], Any]]:
        return {
            "agent_meta.public.v1.Runtime.GetInfo": self.get_info,
            "agent_meta.public.v1.Runtime.GetView": self.get_view,
            "agent_meta.public.v1.Runtime.Doctor": self.doctor,
            "agent_meta.public.v1.Runtime.GetMetrics": self.get_metrics,
            "agent_meta.public.v1.Task.Submit": self.task_submit,
            "agent_meta.public.v1.Task.Get": self.task_get,
            "agent_meta.public.v1.Task.Wait": self.task_wait,
            "agent_meta.public.v1.Task.Cancel": self.task_cancel,
            "agent_meta.public.v1.Artifact.BeginPut": self.artifact_begin_put,
            "agent_meta.public.v1.Artifact.PutChunk": self.artifact_put_chunk,
            "agent_meta.public.v1.Artifact.Put": self.artifact_put,
            "agent_meta.public.v1.Artifact.GetManifest": self.artifact_get_manifest,
            "agent_meta.public.v1.Artifact.Verify": self.artifact_verify,
            "agent_meta.public.v1.Composition.Validate": self.composition_validate,
            "agent_meta.public.v1.Composition.Commit": self.composition_commit,
            "agent_meta.public.v1.Composition.GetRefs": self.composition_get_refs,
            "agent_meta.public.v1.Harness.ValidatePackage": self.harness_validate_package,
            "agent_meta.public.v1.Harness.Get": self.harness_get,
            "agent_meta.public.v1.Harness.List": self.harness_list,
            "agent_meta.public.v1.Harness.Install": self.harness_install,
            "agent_meta.public.v1.Harness.Activate": self.harness_activate,
            "agent_meta.public.v1.Harness.Deactivate": self.harness_deactivate,
            "agent_meta.public.v1.Harness.Uninstall": self.harness_uninstall,
            "agent_meta.public.v1.Graph.Why": self.graph_why,
            "agent_meta.public.v1.Graph.Lineage": self.graph_lineage,
            "agent_meta.public.v1.Evolution.Propose": self.evolution_propose,
            "agent_meta.public.v1.Evolution.RunExperiment": self.evolution_run_experiment,
            "agent_meta.public.v1.Evolution.GetExperiment": self.evolution_get_experiment,
            "agent_meta.public.v1.Evolution.WaitExperiment": self.evolution_wait_experiment,
            "agent_meta.public.v1.Evolution.Promote": self.evolution_promote,
            "agent_meta.public.v1.Evolution.Rollback": self.evolution_rollback,
            "agent_meta.public.v1.Operations.GetOperation": self.operations_get,
            "agent_meta.public.v1.Operations.WaitOperation": self.operations_wait,
            "agent_meta.public.v1.Operations.Backup": self.operations_backup,
            "agent_meta.public.v1.Operations.GcPlan": self.operations_gc_plan,
            "agent_meta.public.v1.Operations.GcApply": self.operations_gc_apply,
        }

    # -- helpers -------------------------------------------------------------
    def _command_status(self, command_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT status FROM commands WHERE command_id = ?", (command_id,)
        ).fetchone()
        return row[0] if row else None

    def _parse_envelope(
        self, request: pub.CommandRequest
    ) -> tuple[CommandEnvelope, Mapping[str, Any]]:
        try:
            body = json.loads(bytes(request.command_envelope_jcs).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed command envelope JCS"
            ) from exc
        if not isinstance(body, dict) or not isinstance(body.get("payload"), dict):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed command envelope JCS"
            )
        payload = body.pop("payload")
        try:
            envelope = CommandEnvelope(payload=payload, **body)
        except TypeError as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed command envelope"
            ) from exc
        return envelope, payload

    def _run_command(
        self, envelope: CommandEnvelope, mutator: Callable
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        result = execute_command(
            self._conn,
            envelope,
            mutator,
            deadline=Deadline.after(self._deadline_us),
        )
        if hasattr(result, "error"):
            raise result.error
        receipt = {
            "command_id": result.command_id,
            "action_id": result.receipt.get("action_id", result.command_id),
            "meta_revision": result.meta_revision,
        }
        return receipt, dict(result.receipt)

    def _internal_envelope(self, payload_type: str) -> CommandEnvelope:
        """Service-owned envelope for the begin/finish halves of long ops."""

        from ...domain.ids import new_uuid7

        return CommandEnvelope(
            command_id="action://" + new_uuid7(),
            realm_id=self._realm_id,
            actor_id=f"principal://service/{new_uuid7()}",
            authority_grant_id=None,
            expected_meta_revision=None,
            causal_parent_action_id=None,
            payload_type=payload_type,
            payload_schema_version=1,
            payload={},
            auth_nonce=None,
            auth_issued_at_us=None,
            auth_signature=None,
        )

    def _read_body_artifact(self, artifact_id: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT manifest_json FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown artifact")
        manifest = json.loads(bytes(row[0]).decode("utf-8"))
        digest = artifact_id.removeprefix("artifact://sha256/")
        if "storage_relpath" not in manifest or "size_bytes" not in manifest:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="artifact has no stored content"
            )
        data = self._cas.open_blob(
            manifest["storage_relpath"], digest, int(manifest["size_bytes"])
        )
        try:
            body = json.loads(bytes(data).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="artifact content is not JSON"
            ) from exc
        if not isinstance(body, dict):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="artifact content is not an object"
            )
        return body

    # -- Runtime -------------------------------------------------------------
    async def get_info(self, request: pub.GetInfoRequest, deadline_us: int) -> pub.RuntimeInfo:
        snap = self._readiness()
        refs = self._conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision"
            " FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone() or (0, 0, 0)
        return pub.RuntimeInfo(
            live=True,
            core_ready=snap.core_ready,
            serving_ready=snap.serving_ready,
            ready=snap.core_ready,  # v1 alias MUST equal core_ready (§41.52)
            core_reasons=list(snap.core_reasons),
            serving_reasons=list(snap.serving_reasons),
            desired_revision=refs[0],
            serving_revision=refs[1],
            realized_revision=refs[2],
        )

    async def get_view(
        self, request: pub.GetViewRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        if request.realm_id and request.realm_id != self._realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown realm")
        if request.HasField("meta_revision") and request.meta_revision:
            view = get_historical_view(self._conn, self._realm_id, request.meta_revision)
        else:
            view = get_current_view(self._conn, self._realm_id)
        body = {
            "realm_id": view.realm_id,
            "epoch_id": view.epoch_id,
            "meta_revision": view.meta_revision,
            "fact_boundary_seq": view.fact_boundary_seq,
            "desired_revision": view.desired_revision,
            "serving_revision": view.serving_revision,
            "realized_revision": view.realized_revision,
            "reconcile_status": view.reconcile_status,
            "state_revision_bindings": dict(view.state_revision_bindings),
            "core_ready": view.core_ready,
            "serving_ready": view.serving_ready,
        }
        return pub.ResourceResponse(resource_jcs=_resource("runtime-view/v1", body))

    async def doctor(self, request: pub.DoctorRequest, deadline_us: int) -> pub.DoctorResponse:
        report = run_integrity_doctor(self._db_path, cas_root=self._data_dir)
        return pub.DoctorResponse(
            report_jcs=canonical_json(
                {
                    "ok": report.ok,
                    "findings": report.findings,
                    "facts_checked": report.facts_checked,
                    "blobs_checked": report.blobs_checked,
                }
            )
        )

    async def get_metrics(
        self, request: pub.GetMetricsRequest, deadline_us: int
    ) -> pub.GetMetricsResponse:
        return pub.GetMetricsResponse(metrics_jcs=canonical_json({}))

    # -- Task ----------------------------------------------------------------
    async def task_submit(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "task.submit/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        snap = self._readiness()
        if not snap.serving_ready:
            raise StableError(
                code=ErrorCode.SERVING_NOT_READY,
                message="task admission requires serving_ready",
                details={"reasons": list(snap.serving_reasons)},
            )
        refs = self._conn.execute(
            "SELECT serving_revision FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if refs is None or not refs[0]:
            raise StableError(
                code=ErrorCode.NO_SERVING_COMPOSITION, message="no serving composition"
            )
        composition_row = self._conn.execute(
            "SELECT composition_id FROM compositions"
            " WHERE realm_id = ? AND revision = ?",
            (self._realm_id, int(refs[0])),
        ).fetchone()
        if composition_row is None:
            raise StableError(
                code=ErrorCode.NO_SERVING_COMPOSITION,
                message="serving revision has no composition",
            )
        budget = payload.get("budget") or {}
        accept = TaskAcceptRequest(
            task_id=None,
            actor_id=envelope.actor_id,
            input_artifact_id=str(payload["input_artifact_id"]),
            serving_composition_id=str(composition_row[0]),
            serving_revision=int(refs[0]),
            budget=TaskBudget(
                max_turns=int(budget.get("max_turns", 32)),
                max_steps=int(budget.get("max_steps", 128)),
                max_model_calls=int(budget.get("max_model_calls", 64)),
                max_effects=int(budget.get("max_effects", 32)),
                max_cost_microunits=int(budget.get("max_cost_microunits", 0)),
            ),
            deadline_at_us=int(payload.get("deadline_at_us") or 0) or None,
        )

        def mutator(txn) -> Mapping[str, Any]:
            return accept_task(accept)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        resource = _resource(
            "task-handle/v1",
            {
                "task_id": extra.get("task_id", ""),
                "root_action_id": extra.get("root_action_id", ""),
                "serving_revision": int(refs[0]),
                "status": TaskStatus.ACCEPTED,
            },
        )
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt), resource_jcs=resource
        )

    async def task_get(
        self, request: pub.GetTaskRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        record = load_task(self._conn, request.task_id)
        if record is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown task")
        body = {
            "task_id": record.task_id,
            "status": record.status,
            "serving_revision": record.serving_revision,
            "result_artifact_id": record.result_artifact_id or "",
            "error": record.error or "",
        }
        return pub.ResourceResponse(resource_jcs=_resource("task-handle/v1", body))

    async def task_wait(
        self, request: pub.WaitTaskRequest, deadline_us: int
    ) -> pub.TaskWaitResponse:
        loop = asyncio.get_running_loop()
        now = self._now_us()
        wait_deadline = now + 60_000_000  # single Wait caps at 60 s (§41.26)
        if request.wait_deadline_at_us:
            wait_deadline = min(wait_deadline, request.wait_deadline_at_us)
        while True:
            record = load_task(self._conn, request.task_id)
            if record is None:
                raise StableError(code=ErrorCode.NOT_FOUND, message="unknown task")
            if record.status in _TERMINAL_TASK_STATUSES:
                body = {
                    "task_id": record.task_id,
                    "status": record.status,
                    "result_artifact_id": record.result_artifact_id or "",
                    "error": record.error or "",
                }
                return pub.TaskWaitResponse(
                    resource_jcs=_resource("task-result/v1", body), terminal=True
                )
            now = self._now_us()
            if now >= wait_deadline:
                body = {
                    "task_id": record.task_id,
                    "status": record.status,
                    "result_artifact_id": record.result_artifact_id or "",
                }
                # Wait timeout ends the RPC, never the Task (§41.26).
                return pub.TaskWaitResponse(
                    resource_jcs=_resource("task-handle/v1", body), terminal=False
                )
            if deadline_us and now >= deadline_us:
                raise StableError(
                    code=ErrorCode.DEADLINE_EXCEEDED, message="request deadline"
                )
            await loop.run_in_executor(None, _sleep_s, 0.02)

    async def task_cancel(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "task.cancel/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )

        def mutator(txn) -> Mapping[str, Any]:
            return request_task_cancel(
                str(payload["task_id"]),
                reason_code=str(payload.get("reason_code", "requested")),
            )(txn)

        receipt, _ = self._run_command(envelope, mutator)
        return pub.MutationResponse(receipt_jcs=canonical_json(receipt))

    # -- Artifact ------------------------------------------------------------
    async def artifact_begin_put(
        self, request: pub.BeginPutRequest, deadline_us: int
    ) -> pub.BeginPutResponse:
        session = self._staging.begin_put(
            expected_size=request.expected_size, expected_sha256=request.expected_sha256
        )
        return pub.BeginPutResponse(
            staging_handle=session.staging_handle,
            chunk_size=session.chunk_size,
            expires_at_us=session.expires_at_us,
        )

    async def artifact_put_chunk(
        self, request: pub.PutChunkRequest, deadline_us: int
    ) -> pub.PutChunkResponse:
        committed = self._staging.put_chunk(
            staging_handle=request.staging_handle,
            offset=request.offset,
            data=bytes(request.data),
            chunk_sha256=request.chunk_sha256,
        )
        return pub.PutChunkResponse(committed_offset=committed)

    async def artifact_put(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "artifact.put/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        relpath = ""
        if self._command_status(envelope.command_id) != "COMMITTED":
            handle = str(payload["source_staging_handle"])
            relpath = self._staging.finalize(staging_handle=handle)
        artifact_id = f"artifact://sha256/{payload['expected_sha256']}"

        def mutator(txn) -> Mapping[str, Any]:
            cur = txn._conn.execute(
                "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            )
            if cur.fetchone()[0]:
                return {"artifact_id": artifact_id, "storage_relpath": relpath}
            txn._conn.execute(
                "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
                " schema_version, created_by, created_at_us, parents_json,"
                " manifest_json, integrity_status)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'VALID')",
                (
                    artifact_id,
                    str(payload["kind"]),
                    str(payload["media_type"]),
                    int(payload["expected_size"]),
                    1,
                    envelope.actor_id,
                    self._now_us(),
                    canonical_json([str(p) for p in payload.get("parents", [])]),
                    canonical_json(
                        {
                            "storage_relpath": relpath,
                            "size_bytes": int(payload["expected_size"]),
                        }
                    ),
                ),
            )
            return {"artifact_id": artifact_id, "storage_relpath": relpath}

        receipt, extra = self._run_command(envelope, mutator)
        resource = _resource("artifact-manifest/v1", dict(extra))
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt), resource_jcs=resource
        )

    async def artifact_get_manifest(
        self, request: pub.GetArtifactRequest, deadline_us: int
    ) -> pub.ArtifactManifestResponse:
        row = self._conn.execute(
            "SELECT artifact_id, kind, media_type, size_bytes, manifest_json"
            " FROM artifacts WHERE artifact_id = ?",
            (request.artifact_id,),
        ).fetchone()
        if row is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown artifact")
        body = {
            "artifact_id": row[0],
            "kind": row[1],
            "media_type": row[2],
            "size_bytes": row[3],
            **json.loads(bytes(row[4]).decode("utf-8")),
        }
        return pub.ArtifactManifestResponse(
            manifest_jcs=_resource("artifact-manifest/v1", body)
        )

    async def artifact_verify(
        self, request: pub.VerifyArtifactRequest, deadline_us: int
    ) -> pub.VerifyArtifactResponse:
        row = self._conn.execute(
            "SELECT size_bytes, manifest_json FROM artifacts WHERE artifact_id = ?",
            (request.artifact_id,),
        ).fetchone()
        if row is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown artifact")
        manifest = json.loads(bytes(row[1]).decode("utf-8"))
        digest = request.artifact_id.removeprefix("artifact://sha256/")
        try:
            self._cas.open_blob(manifest["storage_relpath"], digest, row[0])
        except StableError as exc:
            return pub.VerifyArtifactResponse(ok=False, reason_code=exc.code)
        return pub.VerifyArtifactResponse(ok=True, reason_code="OK")

    # -- Composition ---------------------------------------------------------
    async def composition_validate(
        self, request: pub.ValidateCompositionRequest, deadline_us: int
    ) -> pub.ValidateCompositionResponse:
        from ...application.reconciler import topological_slots

        body = self._read_body_artifact(request.body_artifact_id)
        issues: list[dict[str, Any]] = []
        if body.get("schema") != "composition/v1":
            issues.append(
                {
                    "code": "SCHEMA_UNSUPPORTED",
                    "severity": "ERROR",
                    "path": "/schema",
                }
            )
            valid = False
        else:
            try:
                topological_slots(body)
                valid = True
            except StableError as exc:
                issues.append(
                    {
                        "code": exc.code,
                        "severity": "ERROR",
                        "path": "/wiring",
                    }
                )
                valid = False
        return pub.ValidateCompositionResponse(
            issues_jcs=canonical_json({"issues": issues, "valid": valid}), valid=valid
        )

    async def composition_commit(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "composition.commit/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        body = self._read_body_artifact(str(payload["composition_body_artifact_id"]))
        row = self._conn.execute(
            "SELECT COALESCE(MAX(desired_revision), 0) FROM composition_refs"
            " WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        created = create_composition(
            CompositionCreateRequest(
                realm_id=self._realm_id,
                body=body,
                created_by=envelope.actor_id,
                revision=int(row[0]) + 1,
            )
        )

        def mutator(txn) -> Mapping[str, Any]:
            return created(txn)

        receipt, extra = self._run_command(envelope, mutator)
        resource = _resource("composition-commit/v1", dict(extra))
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt), resource_jcs=resource
        )

    async def composition_get_refs(
        self, request: pub.GetRefsRequest, deadline_us: int
    ) -> pub.GetRefsResponse:
        row = self._conn.execute(
            "SELECT desired_revision, serving_revision, realized_revision,"
            " reconcile_status FROM composition_refs WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if row is None:
            row = (0, 0, 0, "PENDING")
        return pub.GetRefsResponse(
            desired_revision=row[0],
            serving_revision=row[1],
            realized_revision=row[2],
            reconcile_status=row[3],
        )

    # -- Harness ---------------------------------------------------------------
    async def harness_validate_package(
        self, request: pub.ValidateHarnessPackageRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        body = self._read_body_artifact(request.manifest_artifact_id)
        issues = list(validate_manifest(body))
        return pub.ResourceResponse(
            resource_jcs=_resource(
                "harness-package-validation/v1",
                {
                    "manifest_artifact_id": request.manifest_artifact_id,
                    "valid": not issues,
                    "issues": issues,
                },
            )
        )

    async def harness_get(
        self, request: pub.GetHarnessRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        row = get_harness_row(self._conn, request.harness_id)
        if row is None or row["realm_id"] != self._realm_id:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="harness installation not found",
                details={"harness_id": request.harness_id},
            )
        return pub.ResourceResponse(
            resource_jcs=_resource("harness-installation/v1", row)
        )

    async def harness_list(
        self, request: pub.ListHarnessRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        if request.realm_id and request.realm_id != self._realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown realm")
        rows = list_harness_rows(
            self._conn,
            self._realm_id,
            status=request.status,
            limit=request.limit or 100,
        )
        return pub.ResourceResponse(
            resource_jcs=_resource(
                "harness-list/v1", {"harnesses": rows, "next_cursor": ""}
            )
        )

    async def harness_install(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "harness.install/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        install_request = InstallHarnessRequest(
            realm_id=self._realm_id,
            package_name=str(payload["package_name"]),
            package_version=str(payload["package_version"]),
            manifest_artifact_id=str(payload["manifest_artifact_id"]),
            package_artifact_id=str(payload["package_artifact_id"]),
            contract_fingerprint=str(payload.get("contract_fingerprint", "")),
            installed_by=envelope.actor_id,
        )

        def mutator(txn) -> Mapping[str, Any]:
            return install_harness(install_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("harness-install/v1", dict(extra)),
        )

    async def harness_activate(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "harness.activate/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        body = self._read_body_artifact(str(payload["composition_body_artifact_id"]))
        service_row = self._conn.execute(
            "SELECT principal_id FROM principals WHERE realm_id = ? AND kind = 'SERVICE'",
            (self._realm_id,),
        ).fetchone()
        if service_row is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="runtime Service principal missing; activate refused",
            )
        specs = tuple(
            ScopedGrantSpec(
                subject_id=service_row[0],
                permissions=frozenset({str(item["permission"])}),
                scope_targets=(ScopeTarget(type="REALM_ALL"),),
                expires_at_us=(
                    int(item["expires_at_us"]) if item.get("expires_at_us") else None
                ),
                max_uses=int(item["max_uses"]) if item.get("max_uses") else None,
            )
            for item in payload.get("grant_requests", [])
        )
        activate_request = ActivateHarnessRequest(
            harness_id=str(payload["harness_id"]),
            composition_body=body,
            issuer_grant_id=envelope.actor_id,
            scoped_grants=specs,
            plan_hash=str(payload.get("plan_hash", "")),
            grant_request_hash=str(payload.get("grant_request_hash", "")),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return activate_harness(activate_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("harness-activate/v1", dict(extra)),
        )

    async def harness_deactivate(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "harness.deactivate/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        deactivate_request = DeactivateHarnessRequest(
            harness_id=str(payload["harness_id"]),
            reason_code=str(payload.get("reason_code", "operator_deactivate")),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return deactivate_harness(deactivate_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("harness-deactivate/v1", dict(extra)),
        )

    async def harness_uninstall(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "harness.uninstall/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        uninstall_request = UninstallHarnessRequest(
            harness_id=str(payload["harness_id"]),
            reason_code=str(payload.get("reason_code", "operator_uninstall")),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return uninstall_harness(uninstall_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("harness-uninstall/v1", dict(extra)),
        )

    # -- Evolution -----------------------------------------------------------
    async def evolution_propose(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "evolution.propose/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        proposal_request = SubmitProposalRequest(
            realm_id=self._realm_id,
            hypothesis=str(payload["hypothesis"]),
            source_evidence_ids=tuple(
                str(item) for item in payload.get("source_evidence_ids", ())
            ),
            target_composition_id=str(payload["target_composition_id"]),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return submit_proposal(proposal_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("proposal/v1", dict(extra)),
        )

    async def evolution_run_experiment(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "experiment.run/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        criteria_artifact_id = str(payload["criteria_artifact_id"])
        criteria = self._read_body_artifact(criteria_artifact_id)
        issues = validate_criteria(criteria)
        if issues:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="invalid evaluation criteria document",
                details={"issues": sorted(issues)},
            )
        world_id = str(payload["world_id"])
        world_row = self._conn.execute(
            "SELECT body_json FROM worlds WHERE world_id = ?", (world_id,)
        ).fetchone()
        if world_row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="world not found",
                details={"world_id": world_id},
            )
        world = json.loads(bytes(world_row[0]).decode("utf-8"))
        fixtures: list[Mapping[str, Any]] = []
        for fixture_artifact_id in world.get("fixture_artifact_ids", ()):
            document = self._read_body_artifact(str(fixture_artifact_id))
            entries = document.get("fixtures")
            if isinstance(entries, list):
                fixtures.extend(entries)
            else:
                fixtures.append(document)
        budget_payload = payload.get("budget") or {}
        create_request = CreateExperimentRequest(
            realm_id=self._realm_id,
            candidate_id=str(payload["candidate_id"]),
            baseline_id=str(payload["baseline_id"]),
            world_id=world_id,
            criteria_artifact_id=criteria_artifact_id,
            budget=TaskBudget(
                max_turns=int(budget_payload.get("max_turns", 32)),
                max_steps=int(budget_payload.get("max_steps", 128)),
                max_model_calls=int(budget_payload.get("max_model_calls", 64)),
                max_effects=int(budget_payload.get("max_effects", 32)),
                max_cost_microunits=int(budget_payload.get("max_cost_microunits", 0)),
            ),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return create_experiment(create_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        runner_request = RunExperimentRequest(
            realm_id=self._realm_id,
            experiment_id=str(extra["experiment_id"]),
            criteria_document=criteria,
            evaluator_artifact_id=str(
                payload.get("evaluator_artifact_id") or criteria_artifact_id
            ),
            result_artifact_id=str(
                payload.get("result_artifact_id") or criteria_artifact_id
            ),
            evidence_artifact_id=str(
                payload.get("evidence_artifact_id") or criteria_artifact_id
            ),
            fixtures=tuple(fixtures),
            backend_features=PORTABLE_FEATURES,
        )
        run = run_experiment(
            self._conn, envelope, runner_request, Deadline.after(self._deadline_us)
        )
        resource = _resource(
            "experiment-run/v1", {"experiment_id": extra["experiment_id"], **run}
        )
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt), resource_jcs=resource
        )

    async def evolution_get_experiment(
        self, request: pub.GetExperimentRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        row = get_experiment_row(self._conn, request.experiment_id)
        if row["realm_id"] != self._realm_id:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="experiment not found",
                details={"experiment_id": request.experiment_id},
            )
        return pub.ResourceResponse(resource_jcs=_resource("experiment/v1", row))

    async def evolution_wait_experiment(
        self, request: pub.WaitExperimentRequest, deadline_us: int
    ) -> pub.TaskWaitResponse:
        loop = asyncio.get_running_loop()
        now = self._now_us()
        wait_deadline = now + 60_000_000  # single Wait caps at 60 s (§41.26)
        if request.wait_deadline_at_us:
            wait_deadline = min(wait_deadline, request.wait_deadline_at_us)
        while True:
            row = get_experiment_row(self._conn, request.experiment_id)
            if row["realm_id"] != self._realm_id:
                raise StableError(
                    code=ErrorCode.NOT_FOUND,
                    message="experiment not found",
                    details={"experiment_id": request.experiment_id},
                )
            if row["status"] in _TERMINAL_EXPERIMENT_STATUSES:
                return pub.TaskWaitResponse(
                    resource_jcs=_resource("experiment/v1", row), terminal=True
                )
            now = self._now_us()
            if now >= wait_deadline:
                # Wait timeout ends the RPC, never the Experiment (§41.26).
                return pub.TaskWaitResponse(
                    resource_jcs=_resource("experiment/v1", row), terminal=False
                )
            if deadline_us and now >= deadline_us:
                raise StableError(
                    code=ErrorCode.DEADLINE_EXCEEDED, message="request deadline"
                )
            await loop.run_in_executor(None, _sleep_s, 0.02)

    async def evolution_promote(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "candidate.promote/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        promote_request = PromoteCandidateRequest(
            realm_id=self._realm_id,
            candidate_id=str(payload["candidate_id"]),
            evaluation_id=str(payload["evaluation_id"]),
            expected_serving_revision=int(payload.get("expected_serving_revision", 0)),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return promote_candidate(promote_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("promote/v1", dict(extra)),
        )

    async def evolution_rollback(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "composition.rollback/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        state_revisions = payload.get("expected_state_revisions") or {}
        rollback_request = RollbackCompositionRequest(
            realm_id=self._realm_id,
            target_parent_id=str(payload["target_parent_id"]),
            expected_serving_revision=int(payload.get("expected_serving_revision", 0)),
            state_strategy=str(payload.get("state_strategy", "KEEP_COMPATIBLE")),
            expected_state_revisions=(
                {str(key): str(value) for key, value in state_revisions.items()}
                if state_revisions
                else None
            ),
            reason_code=str(payload.get("reason_code", "operator_rollback")),
        )

        def mutator(txn) -> Mapping[str, Any]:
            return rollback_composition(rollback_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("rollback/v1", dict(extra)),
        )

    # -- Operations ------------------------------------------------------------
    _TERMINAL_OPERATION_STATUSES = frozenset(
        {"SUCCEEDED", "FAILED", "FAILED_RECOVERY", "CANCELLED"}
    )

    async def operations_get(
        self, request: pub.GetOperationRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        row = get_operation_row(self._conn, request.operation_id)
        if row is None or row["realm_id"] != self._realm_id:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="operation not found",
                details={"operation_id": request.operation_id},
            )
        return pub.ResourceResponse(resource_jcs=_resource("operation/v1", row))

    async def operations_wait(
        self, request: pub.WaitOperationRequest, deadline_us: int
    ) -> pub.ResourceResponse:
        loop = asyncio.get_running_loop()
        now = self._now_us()
        wait_deadline = now + 60_000_000  # single Wait caps at 60 s (§41.26)
        if request.wait_deadline_at_us:
            wait_deadline = min(wait_deadline, request.wait_deadline_at_us)
        while True:
            row = get_operation_row(self._conn, request.operation_id)
            if row is None or row["realm_id"] != self._realm_id:
                raise StableError(
                    code=ErrorCode.NOT_FOUND,
                    message="operation not found",
                    details={"operation_id": request.operation_id},
                )
            if row["status"] in self._TERMINAL_OPERATION_STATUSES:
                return pub.ResourceResponse(resource_jcs=_resource("operation/v1", row))
            now = self._now_us()
            if now >= wait_deadline:
                return pub.ResourceResponse(resource_jcs=_resource("operation/v1", row))
            if deadline_us and now >= deadline_us:
                raise StableError(
                    code=ErrorCode.DEADLINE_EXCEEDED, message="request deadline"
                )
            await loop.run_in_executor(None, _sleep_s, 0.02)

    async def operations_backup(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "operations.backup/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        destination = payload.get("absolute_destination")
        expected = payload.get("expected_meta_revision")

        begin_env = self._internal_envelope("operations.control/v1")
        _, begin_extra = self._run_command(
            begin_env,
            lambda txn: begin_operation(
                txn,
                BeginOperationRequest(
                    kind="backup",
                    command_id=begin_env.command_id,
                    request={
                        "absolute_destination": (
                            str(destination) if destination is not None else None
                        ),
                        "expected_meta_revision": expected,
                    },
                ),
            ),
        )
        operation_id = str(begin_extra["operation_id"])
        try:
            outcome = create_backup(
                self._conn,
                self._data_dir,
                Path(str(destination)) if destination is not None else None,
                expected_meta_revision=int(expected) if expected is not None else None,
            )
        except StableError as exc:
            self._run_command(
                self._internal_envelope("operations.control/v1"),
                lambda txn: finish_operation(
                    txn,
                    FinishOperationRequest(
                        operation_id=operation_id,
                        status="FAILED",
                        error={
                            "code": exc.code.name,
                            "message": exc.message,
                            "reason_code": str(
                                (exc.details or {}).get("reason_code", exc.code.name)
                            ),
                        },
                    ),
                ),
            )
            raise
        result = {
            "destination": str(outcome.destination),
            "manifest_sha256": outcome.manifest_sha256,
            "meta_revision": outcome.manifest["meta_revision"],
            "fact_boundary": outcome.manifest["fact_boundary"],
        }
        def finish_mutator(txn) -> Mapping[str, Any]:
            finish_operation(
                txn,
                FinishOperationRequest(
                    operation_id=operation_id, status="SUCCEEDED", result=result
                ),
            )
            _append_backup_fact(txn, operation_id=operation_id, payload=result)
            return {"operation_id": operation_id}

        self._run_command(
            self._internal_envelope("operations.control/v1"), finish_mutator
        )
        return pub.MutationResponse(
            receipt_jcs=canonical_json(
                {"operation_id": operation_id, "status": "SUCCEEDED"}
            ),
            resource_jcs=_resource(
                "backup/v1",
                {"operation_id": operation_id, "status": "SUCCEEDED", **result},
            ),
        )

    async def operations_gc_plan(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "operations.gc-plan/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        built = build_gc_plan(
            self._conn,
            self._cas,
            self._data_dir,
            realm_id=self._realm_id,
            expected_meta_revision=int(payload["expected_meta_revision"]),
            legal_hold_artifact_ids=tuple(
                str(a) for a in payload.get("legal_hold_artifact_ids", [])
            ),
        )
        plan = built["plan"]

        def mutator(txn) -> Mapping[str, Any]:
            return commit_gc_plan(
                realm_id=self._realm_id,
                plan_artifact_id=built["plan_artifact_id"],
                storage_relpath=built["storage_relpath"],
                size_bytes=int(built["size_bytes"]),
                candidate_count=len(plan["candidate_artifact_ids"]),
            )(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource(
                "gc-plan/v1",
                {
                    "plan_artifact_id": built["plan_artifact_id"],
                    "meta_revision": plan["meta_revision"],
                    "candidate_count": len(plan["candidate_artifact_ids"]),
                    "fact_id": extra["fact_id"],
                },
            ),
        )

    async def operations_gc_apply(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "operations.gc-apply/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        plan_artifact_id = str(payload["gc_plan_artifact_id"])
        if int(payload["expected_meta_revision"]) != int(
            self._conn.execute(
                "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
                (self._realm_id,),
            ).fetchone()[0]
        ):
            raise StableError(code=ErrorCode.REVISION_CONFLICT, message="meta revision")

        begin_env = self._internal_envelope("operations.control/v1")
        _, begin_extra = self._run_command(
            begin_env,
            lambda txn: begin_operation(
                txn,
                BeginOperationRequest(
                    kind="gc-apply",
                    command_id=begin_env.command_id,
                    request={
                        "gc_plan_artifact_id": plan_artifact_id,
                        "expected_meta_revision": payload.get(
                            "expected_meta_revision"
                        ),
                    },
                ),
            ),
        )
        operation_id = str(begin_extra["operation_id"])
        # Phase A: re-read the plan; Phase B: tombstone rows + Facts in one
        # command transaction; Phase C: move files (safe to retry).
        entries = validate_gc_plan(
            self._conn,
            self._cas,
            plan_artifact_id=plan_artifact_id,
            realm_id=self._realm_id,
        )
        _, extra = self._run_command(
            self._internal_envelope("operations.control/v1"),
            lambda txn: apply_gc_quarantine(entries, operation_id=operation_id)(txn),
        )
        move_quarantined_to_trash(self._data_dir, entries)
        self._run_command(
            self._internal_envelope("operations.control/v1"),
            lambda txn: finish_operation(
                txn,
                FinishOperationRequest(
                    operation_id=operation_id,
                    status="SUCCEEDED",
                    result={
                        "gc_plan_artifact_id": plan_artifact_id,
                        "quarantined": extra["quarantined"],
                    },
                ),
            ),
        )
        return pub.MutationResponse(
            receipt_jcs=canonical_json(
                {"operation_id": operation_id, "status": "SUCCEEDED"}
            ),
            resource_jcs=_resource(
                "gc-apply/v1",
                {
                    "operation_id": operation_id,
                    "gc_plan_artifact_id": plan_artifact_id,
                    "quarantined": extra["quarantined"],
                },
            ),
        )

    # -- Graph ---------------------------------------------------------------
    async def graph_why(self, request: pub.WhyRequest, deadline_us: int) -> pub.WhyResponse:
        explanation = why_query(
            SqliteEdgeSource(self._conn),
            self._realm_id,
            request.entity_id,
            max_depth=request.max_depth or DEFAULT_MAX_DEPTH,
            max_nodes=request.max_nodes or DEFAULT_MAX_NODES,
            max_bytes=request.max_bytes or DEFAULT_MAX_BYTES,
            cursor=request.cursor or None,
        )
        return pub.WhyResponse(
            result_jcs=canonical_json(asdict(explanation)),
            next_cursor=explanation.continuation_cursor or "",
        )

    async def graph_lineage(
        self, request: pub.LineageRequest, deadline_us: int
    ) -> pub.LineageResponse:
        # UPSTREAM is the reverse walk (why); DOWNSTREAM (and the empty
        # default) is the forward walk (§41.35).
        walk = why_query if request.direction == "UPSTREAM" else lineage_query
        explanation = walk(
            SqliteEdgeSource(self._conn),
            self._realm_id,
            request.entity_id,
            max_depth=request.limit or DEFAULT_MAX_DEPTH,
            max_nodes=request.limit or DEFAULT_MAX_NODES,
            max_bytes=DEFAULT_MAX_BYTES,
            cursor=request.cursor or None,
        )
        return pub.LineageResponse(
            result_jcs=canonical_json(asdict(explanation)),
            next_cursor=explanation.continuation_cursor or "",
        )
