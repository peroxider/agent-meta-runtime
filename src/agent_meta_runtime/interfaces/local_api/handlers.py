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
from ...adapters.crypto import verify_signature
from ...adapters.store.provider_configuration import ConfigureProviderRequest, configure_provider, provider_configuration
from ...domain.ampak import decode_package
from ...domain.provider_profile import load_profile
from ...domain.provider_configuration import configuration_payload
from ...adapters.execution_portable.backend import PORTABLE_FEATURES
from ...domain.host_profile import TRUSTED_HOST_PROFILE_HASH
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
from ...adapters.store.command_authority import authorize_public_command, guard_public_command
from ...adapters.store.task_execution import task_execution
from ...adapters.store.task_trace import task_trace
from ...adapters.store.artifact_content import read_artifact_content
from ...adapters.store.principals import register_principal, delegate_ordinary_grant, revoke_ordinary_grant
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.causal_query import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_NODES,
    lineage as lineage_query,
)
from ...domain.causal_query import why as why_query
from ...domain.envelope import CommandEnvelope
from ...domain.errors import ErrorCode, StableError, error_from_json
from ...domain.authority import ScopeTarget
from ...application.harness_validation import validate_harness_package, validate_activation_composition
from ...domain.semantics import TaskBudget, TaskStatus
from ...domain.task_submission import parse_task_submission
from ...protocols._v1 import public_pb2 as pub
from ...sdk.commands import decode_command
from .staging import ChunkedStaging

__all__ = ["PublicApiHandlers"]

_TERMINAL_TASK_STATUSES = frozenset(
    {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.FAILED_RECOVERY, TaskStatus.TIMED_OUT, TaskStatus.CANCELLED}
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
        backend_features: Mapping[str, str] | None = None,
        trusted_publishers: frozenset[str] = frozenset(),
        builtin_capabilities: Mapping | None = None,
        daemon_instance_id: str | None = None,
        backend_profile_hash: str = TRUSTED_HOST_PROFILE_HASH,
        context_profile_for=None,
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
        self._backend_features = dict(PORTABLE_FEATURES if backend_features is None else backend_features)
        self._trusted_publishers = trusted_publishers
        self._builtin_capabilities = dict(builtin_capabilities or {})
        self._internal_envelopes = {}
        self._daemon_instance_id = daemon_instance_id
        self._backend_profile_hash = backend_profile_hash
        self._context_profile_for = context_profile_for or (lambda composition_id: None)
        self.stop_requested = False

    # -- registry ----------------------------------------------------------
    def handlers(self) -> dict[str, Callable[[Any, int], Any]]:
        return {
            "agent_meta.public.v1.Runtime.GetInfo": self.get_info,
            "agent_meta.public.v1.Runtime.GetView": self.get_view,
            "agent_meta.public.v1.Runtime.Doctor": self.doctor,
            "agent_meta.public.v1.Runtime.GetMetrics": self.get_metrics,
            "agent_meta.public.v1.Runtime.Stop": self.runtime_stop,
            "agent_meta.public.v1.Authority.CreatePrincipal": self.authority_create_principal,
            "agent_meta.public.v1.Authority.Delegate": self.authority_delegate,
            "agent_meta.public.v1.Authority.Revoke": self.authority_revoke,
            "agent_meta.public.v1.Task.Submit": self.task_submit,
            "agent_meta.public.v1.Task.Get": self.task_get,
            "agent_meta.public.v1.Task.GetExecution": self.task_get_execution,
            "agent_meta.public.v1.Task.GetTrace": self.task_get_trace,
            "agent_meta.public.v1.Task.Wait": self.task_wait,
            "agent_meta.public.v1.Task.Cancel": self.task_cancel,
            "agent_meta.public.v1.Artifact.BeginPut": self.artifact_begin_put,
            "agent_meta.public.v1.Artifact.PutChunk": self.artifact_put_chunk,
            "agent_meta.public.v1.Artifact.Put": self.artifact_put,
            "agent_meta.public.v1.Artifact.GetManifest": self.artifact_get_manifest,
            "agent_meta.public.v1.Artifact.GetContent": self.artifact_get_content,
            "agent_meta.public.v1.Artifact.Verify": self.artifact_verify,
            "agent_meta.public.v1.Composition.Validate": self.composition_validate,
            "agent_meta.public.v1.Composition.Commit": self.composition_commit,
            "agent_meta.public.v1.Composition.GetRefs": self.composition_get_refs,
            "agent_meta.public.v1.Harness.ValidatePackage": self.harness_validate_package,
            "agent_meta.public.v1.Harness.Get": self.harness_get,
            "agent_meta.public.v1.Harness.List": self.harness_list,
            "agent_meta.public.v1.Harness.Install": self.harness_install,
            "agent_meta.public.v1.Harness.Activate": self.harness_activate,
            "agent_meta.public.v1.Harness.ConfigureProvider": self.harness_configure_provider,
            "agent_meta.public.v1.Harness.ValidateProviderConfiguration": self.harness_validate_provider_configuration,
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
            envelope = decode_command(bytes(request.command_envelope_jcs))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed command envelope JCS"
            ) from exc
        if envelope.realm_id != self._realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND, message="command realm not served by this endpoint")
        if envelope.payload_schema_version != 1:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="unsupported command payload schema version")
        authorize_public_command(self._conn, envelope, now_us=self._now_us(), replay_lookup=True)
        return envelope, envelope.payload

    def _run_command(
        self, envelope: CommandEnvelope, mutator: Callable
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        internal = self._internal_envelopes.pop(id(envelope), None) is envelope
        result = execute_command(
            self._conn,
            envelope,
            mutator if internal else guard_public_command(envelope, mutator),
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

        service = self._conn.execute("SELECT principal_id FROM principals WHERE realm_id=? AND kind='SERVICE' AND status='ACTIVE' ORDER BY principal_id LIMIT 1", (self._realm_id,)).fetchone()
        if service is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Runtime Service principal unavailable")
        envelope = CommandEnvelope(
            command_id="action://" + new_uuid7(),
            realm_id=self._realm_id,
            actor_id=service[0],
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
        self._internal_envelopes[id(envelope)] = envelope
        return envelope

    def _read_artifact_bytes(self, artifact_id: str) -> bytes:
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
        return self._cas.open_blob(
            manifest["storage_relpath"], digest, int(manifest["size_bytes"])
        )

    def _read_body_artifact(self, artifact_id: str) -> dict[str, Any]:
        data = self._read_artifact_bytes(artifact_id)
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
    async def runtime_stop(self, request: pub.CommandRequest, deadline_us: int) -> pub.MutationResponse:
        from ...domain.fact_catalog import validate_fact_event
        from ...ports.repositories import FactAppendRequest

        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "runtime.stop/v1" or set(payload) != {"instance_id", "reason_code"}:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid runtime stop payload")
        target, reason = payload["instance_id"], payload["reason_code"]
        if not isinstance(target, str) or not target or len(target) > 128 or not isinstance(reason, str) or not reason or len(reason) > 128:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid runtime stop target/reason")
        replay = self._command_status(envelope.command_id) is not None
        if not replay and self._daemon_instance_id is None:
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="endpoint has no daemon lifecycle owner")
        if not replay and target != self._daemon_instance_id:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="stop target is a different daemon incarnation")

        def admit(txn):
            fact_payload = {"instance_id": target, "reason_code": reason}
            validate_fact_event("runtime", "runtime_stopping", 1, fact_payload)
            txn.append_fact(FactAppendRequest(
                entity_type="runtime", entity_id=self._realm_id, event_type="runtime_stopping",
                schema_version=1, payload=fact_payload, actor_id=envelope.actor_id,
                occurred_at_us=txn.recorded_at_us,
            ))
            return {"instance_id": target, "status": "STOPPING"}

        receipt, extra = self._run_command(envelope, admit)
        if extra["instance_id"] == self._daemon_instance_id:
            self.stop_requested = True
        return pub.MutationResponse(receipt_jcs=canonical_json(receipt), resource_jcs=_resource("runtime-stop/v1", extra))

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
        historical = request.HasField("meta_revision") and bool(request.meta_revision)
        if historical:
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
        if not historical:
            snapshot = self._readiness()
            body["core_ready"] = snapshot.core_ready
            body["serving_ready"] = snapshot.serving_ready
            if request.include_backend:
                body["backend_profile"] = {"profile_hash": self._backend_profile_hash, "features": dict(self._backend_features)}
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

    # -- ordinary Authority ---------------------------------------------------
    def _authority_write(self, request, payload_type, factory, resource_type):
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != payload_type:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="unexpected authority payload type")
        if self._command_status(envelope.command_id) == "COMMITTED":
            receipt, resource = self._run_command(envelope, lambda txn: {})
        else:
            if not self._readiness().core_ready:
                raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="authority mutation requires core readiness")
            receipt, resource = self._run_command(envelope, factory(payload))
        return pub.MutationResponse(receipt_jcs=canonical_json(receipt), resource_jcs=_resource(resource_type, resource))

    async def authority_create_principal(self, request: pub.CommandRequest, deadline_us: int) -> pub.MutationResponse:
        return self._authority_write(request, "authority.principal.create/v1", register_principal, "principal-identity/v1")

    async def authority_delegate(self, request: pub.CommandRequest, deadline_us: int) -> pub.MutationResponse:
        return self._authority_write(request, "authority.delegate/v1",
            lambda payload: delegate_ordinary_grant(payload, realm_id=self._realm_id), "authority-grant/v1")

    async def authority_revoke(self, request: pub.CommandRequest, deadline_us: int) -> pub.MutationResponse:
        return self._authority_write(request, "authority.revoke/v1", revoke_ordinary_grant, "authority-grant/v1")

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
        if self._command_status(envelope.command_id) == "COMMITTED":
            receipt, extra = self._run_command(envelope, lambda txn: {})
            return self._task_submission_response(receipt, extra)
        input_reference, budget, task_deadline = parse_task_submission(payload)
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
        from ...adapters.store.surface import build_surface_snapshot
        prepared_surface = build_surface_snapshot(self._conn, realm_id=self._realm_id,
            composition_id=str(composition_row[0]), actor_id=envelope.actor_id,
            backend_profile_hash=self._backend_profile_hash, now_us=self._now_us(),
            pending_use=(envelope.authority_grant_id, envelope.command_id))
        surface_path = self._cas.put(prepared_surface["content"])
        prepared_surface["manifest"] = {"storage_relpath": surface_path, "size_bytes": len(prepared_surface["content"])}
        from ...adapters.store.task_snapshot import acceptance_view
        context_profile = self._context_profile_for(str(composition_row[0]))
        prepared_view = acceptance_view(self._conn, realm_id=self._realm_id,
            actor_id=envelope.actor_id, composition_id=str(composition_row[0]), serving_revision=int(refs[0]),
            surface_artifact_id=prepared_surface["artifact_id"], authority_fingerprint=prepared_surface["authority_fingerprint"],
            backend_profile_hash=self._backend_profile_hash, context_profile_artifact_id=context_profile,
            causal_parent_action_id=envelope.causal_parent_action_id, now_us=self._now_us(),
            pending_use=(envelope.authority_grant_id, envelope.command_id))
        view_path = self._cas.put(prepared_view["content"])
        prepared_view["manifest"] = {"storage_relpath": view_path, "size_bytes": len(prepared_view["content"])}
        accept = TaskAcceptRequest(
            task_id=None,
            actor_id=envelope.actor_id,
            input_artifact_id=input_reference,
            serving_composition_id=str(composition_row[0]),
            serving_revision=int(refs[0]),
            budget=budget,
            deadline_at_us=task_deadline,
            authority_grant_id=envelope.authority_grant_id,
            prepared_surface=prepared_surface,
            prepared_view=prepared_view,
            backend_profile_hash=self._backend_profile_hash,
            context_profile_artifact_id=context_profile,
            causal_parent_action_id=envelope.causal_parent_action_id,
        )

        def mutator(txn) -> Mapping[str, Any]:
            return accept_task(accept)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return self._task_submission_response(receipt, extra)

    def _task_submission_response(self, receipt, extra):
        record = load_task(self._conn, extra["task_id"])
        if record is None:
            raise StableError(code=ErrorCode.DATA_LOSS, message="committed submission has no durable Task")
        resource = _resource(
            "task-handle/v1",
            {
                "task_id": record.task_id,
                "root_action_id": extra["root_action_id"],
                "serving_revision": record.serving_revision,
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

    async def task_get_execution(self, request: pub.GetTaskRequest, deadline_us: int) -> pub.ResourceResponse:
        return pub.ResourceResponse(resource_jcs=task_execution(self._conn, realm_id=self._realm_id, task_id=request.task_id))

    async def task_get_trace(self, request: pub.GetTaskRequest, deadline_us: int) -> pub.ResourceResponse:
        return pub.ResourceResponse(resource_jcs=task_trace(self._conn, realm_id=self._realm_id, task_id=request.task_id))

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

    async def artifact_get_content(self, request: pub.GetArtifactRequest, deadline_us: int) -> pub.ResourceResponse:
        return pub.ResourceResponse(resource_jcs=read_artifact_content(self._conn, self._cas, request.artifact_id))

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
        report = self._validate_package(request.manifest_artifact_id)
        return pub.ResourceResponse(
            resource_jcs=_resource(
                "harness-validation/v1", report,
            )
        )

    def _validate_package(self, manifest_artifact_id: str) -> dict[str, Any]:
        return validate_harness_package(
            manifest_artifact_id,
            read_artifact=self._read_artifact_bytes,
            verify_signature=verify_signature,
            backend_features=self._backend_features,
            trusted_publishers=self._trusted_publishers,
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
            resource_jcs=_resource("harness-installation/v1", {**row,
                "provider_configuration":provider_configuration(self._conn,self._realm_id,request.harness_id)})
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
        # An already committed command must replay its original receipt even
        # if package bytes subsequently become unavailable.
        report = None
        descriptors = []
        if self._command_status(envelope.command_id) != "COMMITTED":
            report = self._validate_package(str(payload["manifest_artifact_id"]))
            if not report["valid"]:
                raise StableError(code=ErrorCode.FAILED_PRECONDITION,
                                  message="package validation failed", details=report)
            manifest = self._read_body_artifact(str(payload["manifest_artifact_id"]))
            if any(payload.get(key) != manifest[key] for key in ("package_name", "package_version", "package_artifact_id")):
                raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="install identity differs from signed manifest")
            if payload.get("contract_fingerprint") not in (None, "", report["contract_fingerprint"]):
                raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="contract fingerprint mismatch")
            descriptors = [self._read_body_artifact(ref) for ref in manifest["capability_descriptor_artifact_ids"]]
        install_request = InstallHarnessRequest(
            realm_id=self._realm_id,
            package_name=str(payload["package_name"]),
            package_version=str(payload["package_version"]),
            manifest_artifact_id=str(payload["manifest_artifact_id"]),
            package_artifact_id=str(payload["package_artifact_id"]),
            contract_fingerprint=report["contract_fingerprint"] if report else str(payload.get("contract_fingerprint", "")),
            installed_by=envelope.actor_id,
            verified_artifact_ids=tuple(report["verified_artifact_ids"]) if report else (),
        )

        def mutator(txn) -> Mapping[str, Any]:
            for descriptor in descriptors:
                serialized = canonical_json(descriptor)
                key = (descriptor["capability_id"], descriptor["descriptor_revision"])
                existing = txn._conn.execute("SELECT descriptor_json FROM capabilities WHERE capability_id=? AND descriptor_revision=?", key).fetchone()
                if existing is not None:
                    if bytes(existing[0]) != serialized:
                        raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="immutable capability descriptor already registered differently")
                else:
                    txn._conn.execute("INSERT INTO capabilities(capability_id, descriptor_revision, artifact_id, descriptor_json, created_at_us) VALUES (?, ?, ?, ?, ?)", (*key, descriptor["artifact_id"], serialized, txn.recorded_at_us))
            return install_harness(install_request)(txn)

        receipt, extra = self._run_command(envelope, mutator)
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource("harness-install/v1", dict(extra)),
        )

    def _prepare_provider_configuration(self,envelope):
        payload=configuration_payload(dict(envelope.payload))
        if envelope.payload_type!='harness.configure-provider/v1' or envelope.expected_meta_revision is None:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider configuration requires exact fields and revision guards')
        operator=self._conn.execute('SELECT e.authority_root_principal_id FROM realms r JOIN epochs e ON e.epoch_id=r.epoch_id AND e.realm_id=r.realm_id WHERE r.realm_id=?',(self._realm_id,)).fetchone()
        if operator is None or envelope.actor_id!=operator[0]:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider credential binding requires the current Root operator')
        installation=get_harness_row(self._conn,payload['harness_id'])
        if installation is None or installation['realm_id']!=self._realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND,message='Provider configuration installation not found')
        if installation['status']=='UNINSTALLED':
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Provider configuration installation is uninstalled')
        current=self._conn.execute('SELECT current_meta_revision FROM realms WHERE realm_id=?',(self._realm_id,)).fetchone()[0]
        old=provider_configuration(self._conn,self._realm_id,payload['harness_id'])
        if (envelope.expected_meta_revision!=current
                or payload['expected_configuration_revision']!=(old['configuration_revision'] if old else 0)):
            raise StableError(code=ErrorCode.REVISION_CONFLICT,message='Provider configuration revision guard changed')
        profile_preview=None
        if payload['enabled']:
            report=self._validate_package(installation['manifest_artifact_id'])
            if not report['valid'] or report['trust_class']!='builtin_or_signed':
                raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Provider configuration requires a valid explicitly trusted package')
            manifest=self._read_body_artifact(installation['manifest_artifact_id'])
            package,_=decode_package(self._read_artifact_bytes(installation['package_artifact_id']))
            composition=self._read_body_artifact(manifest['composition_template_artifact_id'])
            slot=composition.get('slots',{}).get('model',{})
            declared=package.package.runtime_constraints.get('provider_profile_artifact_id')
            descriptors=[self._read_body_artifact(ref) for ref in manifest['capability_descriptor_artifact_ids']]
            matching=[value for value in descriptors if value['capability_id']==payload['capability_id']
                and value['descriptor_revision']==slot.get('descriptor_revision')]
            if (declared!=payload['profile_artifact_id'] or slot.get('capability_id')!=payload['capability_id']
                    or slot.get('artifact_id')!=installation['package_artifact_id'] or len(matching)!=1
                    or matching[0]['artifact_id']!=installation['package_artifact_id']
                    or matching[0].get('runtime_constraints',{}).get('provider_profile_artifact_id')!=declared
                    or not any('model.invoke' in op['effects'] for op in matching[0]['operations'])):
                raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider binding differs from signed package model/profile declaration')
            profile,closure=load_profile(payload['profile_artifact_id'],self._read_artifact_bytes)
            if profile.policy.profile=='PUBLIC_HTTPS' and (not isinstance(payload['credential_handle'],str)
                    or not payload['credential_handle'].startswith('credential://windows-dpapi/')):
                raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='public Provider configuration requires protected credential handles')
            profile_preview={'model_id':profile.model_id,'destination':profile.policy.to_json(),
                'tokenizer_artifact_id':profile.tokenizer_artifact_id,'price_policy_artifact_id':profile.price_policy_artifact_id,
                'currency':profile.pricing.currency if profile.pricing else None,
                'pricing_version':profile.pricing.pricing_version if profile.pricing else None,
                'maximum_output_tokens':profile.maximum_output_tokens}
        else:
            if old is None or any(payload[key]!=old[key] for key in ('capability_id','profile_artifact_id','credential_handle')):
                raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='disabled Provider binding must identify the existing configuration')
            closure=tuple(old['verified_artifact_ids'])
        prepared=ConfigureProviderRequest(self._realm_id,payload['harness_id'],installation['package_artifact_id'],
            payload['capability_id'],payload['profile_artifact_id'],payload['credential_handle'],
            payload['expected_configuration_revision'],payload['enabled'],closure)
        return prepared,{'valid':True,'configuration':payload,'profile':profile_preview,
            'expected_meta_revision':envelope.expected_meta_revision,'required_permissions':['harness.activate'],
            'required_principal':'CURRENT_EPOCH_ROOT_OPERATOR','will_execute_model':False}

    async def harness_validate_provider_configuration(self,request: pub.CommandRequest,deadline_us: int) -> pub.ResourceResponse:
        envelope,_=self._parse_envelope(request)
        _,report=self._prepare_provider_configuration(envelope)
        return pub.ResourceResponse(resource_jcs=_resource('harness-provider-validation/v1',report))

    async def harness_configure_provider(self, request: pub.CommandRequest, deadline_us: int) -> pub.MutationResponse:
        envelope,_=self._parse_envelope(request)
        if envelope.payload_type!='harness.configure-provider/v1':
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='unexpected Provider configuration command type')
        if self._command_status(envelope.command_id)=='COMMITTED':
            receipt,extra=self._run_command(envelope,lambda txn:{})
            return pub.MutationResponse(receipt_jcs=canonical_json(receipt),resource_jcs=_resource('harness-provider-configuration/v1',extra))
        prepared,_=self._prepare_provider_configuration(envelope)
        receipt,extra=self._run_command(envelope,configure_provider(prepared))
        return pub.MutationResponse(receipt_jcs=canonical_json(receipt),resource_jcs=_resource('harness-provider-configuration/v1',extra))

    async def harness_activate(
        self, request: pub.CommandRequest, deadline_us: int
    ) -> pub.MutationResponse:
        envelope, payload = self._parse_envelope(request)
        if envelope.payload_type != "harness.activate/v1":
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"unexpected payload_type {envelope.payload_type}",
            )
        if self._command_status(envelope.command_id) == "COMMITTED":
            receipt, extra = self._run_command(envelope, lambda txn: {})
            return pub.MutationResponse(receipt_jcs=canonical_json(receipt), resource_jcs=_resource("harness-activate/v1", extra))
        installation = get_harness_row(self._conn, str(payload["harness_id"]))
        if installation is None or installation["realm_id"] != self._realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND, message="harness installation not found")
        validation = self._validate_package(installation["manifest_artifact_id"])
        if not validation["valid"]:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="package validation failed before activation", details=validation)
        body = self._read_body_artifact(str(payload["composition_body_artifact_id"]))
        manifest = self._read_body_artifact(installation["manifest_artifact_id"])
        declared_grants = self._read_body_artifact(manifest["grant_requests_artifact_id"])["requests"]
        if canonical_json(payload.get("grant_requests", [])) != canonical_json(declared_grants):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="activation grant requests differ from signed package")
        if (payload.get("plan_hash") != validation["plan_hash"]
                or payload.get("grant_request_hash") != sha256_hex(canonical_json(declared_grants))):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="activation plan or grant-request hash differs")
        if envelope.expected_meta_revision is None or type(payload.get("expected_serving_revision")) is not int or payload["expected_serving_revision"] < 0:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="activation requires signed expected meta/serving revisions")
        composition_issues = validate_activation_composition(body, manifest,
            realm_id=self._realm_id, read_artifact=self._read_artifact_bytes,
            trust_class=validation["trust_class"], backend_features=self._backend_features,
            builtin_catalog=self._builtin_capabilities)
        if composition_issues:
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="activation composition invalid", details={"issues": composition_issues})
        service_rows = self._conn.execute(
            "SELECT principal_id FROM principals WHERE realm_id = ? AND kind = 'SERVICE' AND status='ACTIVE'",
            (self._realm_id,),
        ).fetchall()
        if len(service_rows) != 1:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="runtime Service principal missing or ambiguous; activate refused",
            )
        specs = tuple(
            ScopedGrantSpec(
                subject_id=service_rows[0][0],
                permissions=frozenset({str(item["permission"])}),
                scope_targets=tuple(ScopeTarget(**target) for target in item["scope"]["targets"]),
                expires_at_us=(
                    int(item["expires_at_us"]) if item.get("expires_at_us") is not None else None
                ),
                max_uses=int(item["max_uses"]) if item.get("max_uses") is not None else None,
            )
            for item in payload.get("grant_requests", [])
        )
        activate_request = ActivateHarnessRequest(
            harness_id=str(payload["harness_id"]),
            composition_body=body,
            issuer_grant_id=envelope.authority_grant_id,
            scoped_grants=specs,
            plan_hash=str(payload.get("plan_hash", "")),
            grant_request_hash=str(payload.get("grant_request_hash", "")),
        )

        def mutator(txn) -> Mapping[str, Any]:
            kind = txn._conn.execute("SELECT kind FROM principals WHERE principal_id=?", (envelope.actor_id,)).fetchone()
            if kind is None or kind[0] != "OPERATOR_ROOT":
                raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Harness activation requires an operator Root signature")
            serving = txn._conn.execute("SELECT serving_revision FROM composition_refs WHERE realm_id=?", (self._realm_id,)).fetchone()
            if serving is None or serving[0] != payload["expected_serving_revision"]:
                raise StableError(code=ErrorCode.REVISION_CONFLICT, message="activation serving revision changed")
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
            backend_features=self._backend_features,
        )
        def execute_step(conn, _caller_envelope, mutator, *, deadline):
            # These are Runtime-owned continuations of the admitted experiment.
            # Never copy the caller's signature/nonce onto a different command.
            internal = self._internal_envelope("experiment.control/v1")
            self._internal_envelopes.pop(id(internal))
            return execute_command(conn, internal, mutator, deadline=deadline)

        run = run_experiment(
            self._conn, envelope, runner_request, Deadline.after(self._deadline_us),
            execute=execute_step,
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

        replay = self._command_status(envelope.command_id) is not None
        def admit(txn):
            current = txn._conn.execute("SELECT current_meta_revision FROM realms WHERE realm_id=?", (self._realm_id,)).fetchone()[0]
            if expected is not None and int(expected) != current:
                raise StableError(code=ErrorCode.REVISION_CONFLICT, message="backup meta revision changed")
            return begin_operation(txn, BeginOperationRequest(
                kind="backup", command_id=envelope.command_id,
                request={"absolute_destination": str(destination) if destination is not None else None,
                         "expected_meta_revision": expected},
            ))
        receipt, begin_extra = self._run_command(envelope, admit)
        operation_id = str(begin_extra["operation_id"])
        if replay:
            return self._operation_response(receipt, operation_id, "backup/v1")
        try:
            outcome = create_backup(
                self._conn,
                self._data_dir,
                Path(str(destination)) if destination is not None else None,
                # The revision guard was checked in the admission transaction.
                # The backup includes that transaction's durable operation row.
                expected_meta_revision=None,
            )
        except StableError as exc:
            self._run_command(
                self._internal_envelope("operations.control/v1"),
                lambda txn: finish_operation(
                    txn,
                    FinishOperationRequest(
                        operation_id=operation_id,
                        status="FAILED",
                        error=exc.to_json(),
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
        return self._operation_response(receipt, operation_id, "backup/v1")

    def _operation_response(self, receipt, operation_id, resource_type):
        row = get_operation_row(self._conn, operation_id)
        if row["error"] is not None:
            if row["status"] == "FAILED_RECOVERY":
                raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                                  message="operation outcome requires recovery; retry will not repeat effects",
                                  details={"operation_id": operation_id, **row["error"]})
            raise error_from_json(row["error"])
        return pub.MutationResponse(
            receipt_jcs=canonical_json(receipt),
            resource_jcs=_resource(resource_type, {
                "operation_id": operation_id, "status": row["status"], **(row["result"] or {}),
            }),
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
        replay = self._command_status(envelope.command_id) is not None
        entries = []
        def admit_and_quarantine(txn):
            current = txn._conn.execute("SELECT current_meta_revision FROM realms WHERE realm_id=?", (self._realm_id,)).fetchone()[0]
            if int(payload["expected_meta_revision"]) != current:
                raise StableError(code=ErrorCode.REVISION_CONFLICT, message="meta revision")
            # Plan validation and tombstones share the authorization transaction.
            # Recording an operation first would itself make the plan stale.
            entries.extend(validate_gc_plan(txn._conn, self._cas,
                plan_artifact_id=plan_artifact_id, realm_id=self._realm_id))
            operation = begin_operation(txn, BeginOperationRequest(
                kind="gc-apply", command_id=envelope.command_id,
                request={"gc_plan_artifact_id": plan_artifact_id,
                         "expected_meta_revision": payload["expected_meta_revision"]},
            ))
            quarantined = apply_gc_quarantine(entries, operation_id=operation["operation_id"])(txn)
            return {**operation, **quarantined}
        receipt, extra = self._run_command(envelope, admit_and_quarantine)
        operation_id = str(extra["operation_id"])
        if replay:
            # A RUNNING operation after interruption requires recovery; never
            # repeat a filesystem effect on an ambiguous caller retry.
            return self._operation_response(receipt, operation_id, "gc-apply/v1")
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
        return self._operation_response(receipt, operation_id, "gc-apply/v1")

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
