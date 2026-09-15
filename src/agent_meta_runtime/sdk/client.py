"""Public Python SDK for the Agent Meta Runtime Public API v1 (§41.52).

The SDK is the only supported programmatic surface: it speaks the frozen
protobuf wire format over an injected async ``Transport`` and exposes
plain dataclasses and dicts — never repositories, unit-of-work objects,
storage adapters, or private protobuf symbols. Mutations build the
canonical ``CommandEnvelope`` JCS (§41.46 idempotency fields included)
and surface the ``MutationReceipt`` plus the created resource. Wire
errors are raised as :class:`~agent_meta_runtime.domain.errors.StableError`
so SDK callers handle one error model.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from ..domain.canonical import canonical_json
from ..domain.envelope import CommandEnvelope
from ..domain.ids import new_uuid7
from ..protocols._v1 import public_pb2 as pub

__all__ = [
    "AgentMetaClient",
    "MutationResult",
    "RuntimeInfo",
    "StagingSession",
    "TaskHandle",
    "Transport",
]


class Transport(Protocol):
    """Async request/response channel carrying serialized Public API messages."""

    async def call(
        self, method: str, request: bytes, *, deadline_us: int | None = None
    ) -> bytes:
        """Send one ``RpcEnvelope``-framed request; return the response frame."""
        ...  # pragma: no cover

    async def close(self) -> None:  # pragma: no cover
        ...


@dataclass(frozen=True, slots=True)
class RuntimeInfo:
    live: bool
    core_ready: bool
    serving_ready: bool
    core_reasons: tuple[str, ...]
    serving_reasons: tuple[str, ...]
    desired_revision: int
    serving_revision: int
    realized_revision: int


@dataclass(frozen=True, slots=True)
class MutationResult:
    receipt: Mapping[str, Any]
    resource: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class StagingSession:
    staging_handle: str
    chunk_size: int
    expires_at_us: int


@dataclass(frozen=True, slots=True)
class TaskHandle:
    task_id: str
    root_action_id: str
    serving_revision: int
    status: str


def _jcs_to_dict(raw: bytes) -> dict[str, Any]:
    return dict(json.loads(bytes(raw).decode("utf-8")))


class AgentMetaClient:
    """Typed facade over the Public API v1 method registry."""

    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    async def aclose(self) -> None:
        await self._transport.close()

    # -- helpers -------------------------------------------------------------
    def build_envelope_jcs(
        self,
        *,
        realm_id: str,
        actor_id: str,
        payload_type: str,
        payload: Mapping[str, Any],
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
        causal_parent_action_id: str | None = None,
    ) -> str:
        """Canonical CommandEnvelope JCS for one mutation (§41.46).

        Also used by the CLI ``--dry-run`` path, which validates the plan
        without sending it.
        """

        envelope = CommandEnvelope(
            command_id="task://" + new_uuid7(),
            realm_id=realm_id,
            actor_id=actor_id,
            authority_grant_id=authority_grant_id,
            expected_meta_revision=expected_meta_revision,
            causal_parent_action_id=causal_parent_action_id,
            payload_type=payload_type,
            payload_schema_version=1,
            payload=dict(payload),
            auth_nonce=None,
            auth_issued_at_us=None,
            auth_signature=None,
        )
        body: dict[str, Any] = {
            field: getattr(envelope, field)
            for field in (
                "command_id",
                "realm_id",
                "actor_id",
                "authority_grant_id",
                "expected_meta_revision",
                "causal_parent_action_id",
                "payload_type",
                "payload_schema_version",
                "auth_nonce",
                "auth_issued_at_us",
                "auth_signature",
            )
        }
        body["payload"] = dict(envelope.payload)
        return canonical_json(body).decode("utf-8")

    async def _mutate(
        self, method: str, envelope_jcs: str, *, deadline_us: int | None = None
    ) -> MutationResult:
        request = pub.CommandRequest(command_envelope_jcs=envelope_jcs.encode("utf-8"))
        response = await self._call(method, request, pub.MutationResponse, deadline_us)
        return MutationResult(
            receipt=_jcs_to_dict(response.receipt_jcs),
            resource=_jcs_to_dict(response.resource_jcs)
            if response.resource_jcs
            else None,
        )

    async def _call(
        self,
        method: str,
        request: Any,
        response_type: Any,
        deadline_us: int | None = None,
    ) -> Any:
        raw = await self._transport.call(
            method, request.SerializeToString(), deadline_us=deadline_us
        )
        response = response_type()
        response.ParseFromString(raw)
        return response

    # -- Runtime -------------------------------------------------------------
    async def get_info(self) -> RuntimeInfo:
        info = await self._call(
            "agent_meta.public.v1.Runtime.GetInfo", pub.GetInfoRequest(), pub.RuntimeInfo
        )
        return RuntimeInfo(
            live=bool(info.live),
            core_ready=bool(info.core_ready),
            serving_ready=bool(info.serving_ready),
            core_reasons=tuple(info.core_reasons),
            serving_reasons=tuple(info.serving_reasons),
            desired_revision=info.desired_revision,
            serving_revision=info.serving_revision,
            realized_revision=info.realized_revision,
        )

    async def get_view(self, meta_revision: int | None = None) -> dict[str, Any]:
        request = pub.GetViewRequest()
        if meta_revision is not None:
            request.meta_revision = meta_revision
        response = await self._call(
            "agent_meta.public.v1.Runtime.GetView", request, pub.ResourceResponse
        )
        return _jcs_to_dict(response.resource_jcs)

    async def doctor(self) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Runtime.Doctor", pub.DoctorRequest(), pub.DoctorResponse
        )
        return _jcs_to_dict(response.report_jcs)

    # -- Task ----------------------------------------------------------------
    async def submit_task(
        self,
        *,
        realm_id: str,
        actor_id: str,
        input_artifact_id: str,
        budget: Mapping[str, Any] | None = None,
        deadline_at_us: int | None = None,
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> TaskHandle:
        payload: dict[str, Any] = {"input_artifact_id": input_artifact_id}
        if budget:
            payload["budget"] = dict(budget)
        if deadline_at_us is not None:
            payload["deadline_at_us"] = deadline_at_us
        result = await self._mutate(
            "agent_meta.public.v1.Task.Submit",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="task.submit/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )
        resource = result.resource or {}
        return TaskHandle(
            task_id=str(resource.get("task_id", "")),
            root_action_id=str(resource.get("root_action_id", "")),
            serving_revision=int(resource.get("serving_revision", 0)),
            status=str(resource.get("status", "")),
        )

    async def get_task(self, task_id: str) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Task.Get",
            pub.GetTaskRequest(task_id=task_id),
            pub.ResourceResponse,
        )
        return _jcs_to_dict(response.resource_jcs)

    async def wait_task(
        self, task_id: str, *, timeout_s: float = 60.0
    ) -> tuple[dict[str, Any], bool]:
        """Wait for terminal state; ``(resource, terminal)`` — timeout is not an error."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_s
        response = await self._call(
            "agent_meta.public.v1.Task.Wait",
            pub.WaitTaskRequest(task_id=task_id, wait_deadline_at_us=0),
            pub.TaskWaitResponse,
            deadline_us=int(timeout_s * 1_000_000),
        )
        return _jcs_to_dict(response.resource_jcs), bool(response.terminal)

    async def cancel_task(
        self, *, realm_id: str, actor_id: str, task_id: str, reason_code: str = "requested"
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Task.Cancel",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="task.cancel/v1",
                payload={"task_id": task_id, "reason_code": reason_code},
            ),
        )

    # -- Artifact ------------------------------------------------------------
    async def begin_put(self, expected_size: int, expected_sha256: str) -> StagingSession:
        response = await self._call(
            "agent_meta.public.v1.Artifact.BeginPut",
            pub.BeginPutRequest(expected_size=expected_size, expected_sha256=expected_sha256),
            pub.BeginPutResponse,
        )
        return StagingSession(
            staging_handle=response.staging_handle,
            chunk_size=response.chunk_size,
            expires_at_us=response.expires_at_us,
        )

    async def put_chunk(self, staging_handle: str, offset: int, data: bytes) -> int:
        response = await self._call(
            "agent_meta.public.v1.Artifact.PutChunk",
            pub.PutChunkRequest(
                staging_handle=staging_handle,
                offset=offset,
                data=data,
                chunk_sha256=hashlib.sha256(data).hexdigest(),
            ),
            pub.PutChunkResponse,
        )
        return response.committed_offset

    async def put_artifact(
        self,
        *,
        realm_id: str,
        actor_id: str,
        content: bytes,
        kind: str,
        media_type: str,
        parents: list[str] | None = None,
        authority_grant_id: str | None = None,
    ) -> dict[str, Any]:
        """Two-phase upload (§41.46) then the ``artifact.put`` command."""

        digest = hashlib.sha256(content).hexdigest()
        session = await self.begin_put(len(content), digest)
        offset = 0
        while offset < len(content):
            offset = await self.put_chunk(
                session.staging_handle, offset, content[offset : offset + session.chunk_size]
            )
        result = await self._mutate(
            "agent_meta.public.v1.Artifact.Put",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="artifact.put/v1",
                payload={
                    "source_staging_handle": session.staging_handle,
                    "expected_sha256": digest,
                    "expected_size": len(content),
                    "kind": kind,
                    "media_type": media_type,
                    "parents": list(parents or []),
                },
                authority_grant_id=authority_grant_id,
            ),
        )
        return dict(result.resource or {"artifact_id": f"artifact://sha256/{digest}"})

    async def get_artifact_manifest(self, artifact_id: str) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Artifact.GetManifest",
            pub.GetArtifactRequest(artifact_id=artifact_id),
            pub.ArtifactManifestResponse,
        )
        return _jcs_to_dict(response.manifest_jcs)

    async def verify_artifact(self, artifact_id: str) -> tuple[bool, str]:
        response = await self._call(
            "agent_meta.public.v1.Artifact.Verify",
            pub.VerifyArtifactRequest(artifact_id=artifact_id),
            pub.VerifyArtifactResponse,
        )
        return bool(response.ok), str(response.reason_code)

    # -- Composition ---------------------------------------------------------
    async def validate_composition(
        self, body_artifact_id: str
    ) -> tuple[bool, list[dict[str, Any]]]:
        response = await self._call(
            "agent_meta.public.v1.Composition.Validate",
            pub.ValidateCompositionRequest(body_artifact_id=body_artifact_id),
            pub.ValidateCompositionResponse,
        )
        report = _jcs_to_dict(response.issues_jcs)
        return bool(response.valid), list(report.get("issues", []))

    async def commit_composition(
        self,
        *,
        realm_id: str,
        actor_id: str,
        body_artifact_id: str,
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Composition.Commit",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="composition.commit/v1",
                payload={"composition_body_artifact_id": body_artifact_id},
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def get_refs(self) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Composition.GetRefs",
            pub.GetRefsRequest(),
            pub.GetRefsResponse,
        )
        return {
            "desired_revision": response.desired_revision,
            "serving_revision": response.serving_revision,
            "realized_revision": response.realized_revision,
            "reconcile_status": response.reconcile_status,
        }

    # -- Harness ---------------------------------------------------------------
    async def validate_harness_package(
        self, manifest_artifact_id: str
    ) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Harness.ValidatePackage",
            pub.ValidateHarnessPackageRequest(manifest_artifact_id=manifest_artifact_id),
            pub.ResourceResponse,
        )
        return _jcs_to_dict(response.resource_jcs)

    async def get_harness(self, harness_id: str) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Harness.Get",
            pub.GetHarnessRequest(harness_id=harness_id),
            pub.ResourceResponse,
        )
        return _jcs_to_dict(response.resource_jcs)

    async def list_harnesses(
        self, *, status: str = "", limit: int | None = None
    ) -> list[dict[str, Any]]:
        request = pub.ListHarnessRequest(status=status)
        if limit:
            request.limit = limit
        response = await self._call(
            "agent_meta.public.v1.Harness.List", request, pub.ResourceResponse
        )
        return list(_jcs_to_dict(response.resource_jcs).get("harnesses", []))

    async def install_harness(
        self,
        *,
        realm_id: str,
        actor_id: str,
        package_name: str,
        package_version: str,
        manifest_artifact_id: str,
        package_artifact_id: str,
        contract_fingerprint: str = "",
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Harness.Install",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="harness.install/v1",
                payload={
                    "package_name": package_name,
                    "package_version": package_version,
                    "manifest_artifact_id": manifest_artifact_id,
                    "package_artifact_id": package_artifact_id,
                    "contract_fingerprint": contract_fingerprint,
                },
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def activate_harness(
        self,
        *,
        realm_id: str,
        actor_id: str,
        harness_id: str,
        composition_body_artifact_id: str,
        grant_requests: list[dict[str, Any]] | None = None,
        plan_hash: str = "",
        grant_request_hash: str = "",
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Harness.Activate",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="harness.activate/v1",
                payload={
                    "harness_id": harness_id,
                    "composition_body_artifact_id": composition_body_artifact_id,
                    "grant_requests": list(grant_requests or []),
                    "plan_hash": plan_hash,
                    "grant_request_hash": grant_request_hash,
                },
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def deactivate_harness(
        self,
        *,
        realm_id: str,
        actor_id: str,
        harness_id: str,
        reason_code: str = "operator_deactivate",
        authority_grant_id: str | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Harness.Deactivate",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="harness.deactivate/v1",
                payload={"harness_id": harness_id, "reason_code": reason_code},
                authority_grant_id=authority_grant_id,
            ),
        )

    async def uninstall_harness(
        self,
        *,
        realm_id: str,
        actor_id: str,
        harness_id: str,
        reason_code: str = "operator_uninstall",
        authority_grant_id: str | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Harness.Uninstall",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="harness.uninstall/v1",
                payload={"harness_id": harness_id, "reason_code": reason_code},
                authority_grant_id=authority_grant_id,
            ),
        )

    # -- Evolution -----------------------------------------------------------
    async def propose(
        self,
        *,
        realm_id: str,
        actor_id: str,
        hypothesis: str,
        target_composition_id: str,
        source_evidence_ids: list[str] | None = None,
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Evolution.Propose",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="evolution.propose/v1",
                payload={
                    "hypothesis": hypothesis,
                    "source_evidence_ids": list(source_evidence_ids or []),
                    "target_composition_id": target_composition_id,
                },
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def run_experiment(
        self,
        *,
        realm_id: str,
        actor_id: str,
        candidate_id: str,
        baseline_id: str,
        world_id: str,
        criteria_artifact_id: str,
        budget: Mapping[str, Any] | None = None,
        evaluator_artifact_id: str | None = None,
        result_artifact_id: str | None = None,
        evidence_artifact_id: str | None = None,
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        payload: dict[str, Any] = {
            "candidate_id": candidate_id,
            "baseline_id": baseline_id,
            "world_id": world_id,
            "criteria_artifact_id": criteria_artifact_id,
        }
        if budget:
            payload["budget"] = dict(budget)
        if evaluator_artifact_id:
            payload["evaluator_artifact_id"] = evaluator_artifact_id
        if result_artifact_id:
            payload["result_artifact_id"] = result_artifact_id
        if evidence_artifact_id:
            payload["evidence_artifact_id"] = evidence_artifact_id
        return await self._mutate(
            "agent_meta.public.v1.Evolution.RunExperiment",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="experiment.run/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def get_experiment(self, experiment_id: str) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Evolution.GetExperiment",
            pub.GetExperimentRequest(experiment_id=experiment_id),
            pub.ResourceResponse,
        )
        return _jcs_to_dict(response.resource_jcs)

    async def wait_experiment(
        self, experiment_id: str, *, timeout_s: float = 60.0
    ) -> tuple[dict[str, Any], bool]:
        """Wait for terminal Experiment status; timeout is not an error."""

        response = await self._call(
            "agent_meta.public.v1.Evolution.WaitExperiment",
            pub.WaitExperimentRequest(experiment_id=experiment_id, wait_deadline_at_us=0),
            pub.TaskWaitResponse,
            deadline_us=int(timeout_s * 1_000_000),
        )
        return _jcs_to_dict(response.resource_jcs), bool(response.terminal)

    async def promote_candidate(
        self,
        *,
        realm_id: str,
        actor_id: str,
        candidate_id: str,
        evaluation_id: str,
        expected_serving_revision: int = 0,
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Evolution.Promote",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="candidate.promote/v1",
                payload={
                    "candidate_id": candidate_id,
                    "evaluation_id": evaluation_id,
                    "expected_serving_revision": expected_serving_revision,
                },
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    async def rollback_composition(
        self,
        *,
        realm_id: str,
        actor_id: str,
        target_parent_id: str,
        expected_serving_revision: int = 0,
        state_strategy: str = "KEEP_COMPATIBLE",
        expected_state_revisions: Mapping[str, str] | None = None,
        reason_code: str = "operator_rollback",
        authority_grant_id: str | None = None,
        expected_meta_revision: int | None = None,
    ) -> MutationResult:
        payload: dict[str, Any] = {
            "target_parent_id": target_parent_id,
            "expected_serving_revision": expected_serving_revision,
            "state_strategy": state_strategy,
            "reason_code": reason_code,
        }
        if expected_state_revisions:
            payload["expected_state_revisions"] = dict(expected_state_revisions)
        return await self._mutate(
            "agent_meta.public.v1.Evolution.Rollback",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="composition.rollback/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
            ),
        )

    # -- Operations ------------------------------------------------------------
    async def backup(
        self,
        *,
        realm_id: str,
        actor_id: str,
        absolute_destination: str | None = None,
        expected_meta_revision: int | None = None,
        authority_grant_id: str | None = None,
    ) -> MutationResult:
        payload: dict[str, Any] = {}
        if absolute_destination is not None:
            payload["absolute_destination"] = absolute_destination
        if expected_meta_revision is not None:
            payload["expected_meta_revision"] = expected_meta_revision
        return await self._mutate(
            "agent_meta.public.v1.Operations.Backup",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="operations.backup/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
            ),
        )

    async def gc_plan(
        self,
        *,
        realm_id: str,
        actor_id: str,
        expected_meta_revision: int,
        legal_hold_artifact_ids: Sequence[str] = (),
        authority_grant_id: str | None = None,
    ) -> MutationResult:
        payload: dict[str, Any] = {"expected_meta_revision": expected_meta_revision}
        if legal_hold_artifact_ids:
            payload["legal_hold_artifact_ids"] = list(legal_hold_artifact_ids)
        return await self._mutate(
            "agent_meta.public.v1.Operations.GcPlan",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="operations.gc-plan/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
            ),
        )

    async def gc_apply(
        self,
        *,
        realm_id: str,
        actor_id: str,
        gc_plan_artifact_id: str,
        expected_meta_revision: int,
        authority_grant_id: str | None = None,
    ) -> MutationResult:
        return await self._mutate(
            "agent_meta.public.v1.Operations.GcApply",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="operations.gc-apply/v1",
                payload={
                    "gc_plan_artifact_id": gc_plan_artifact_id,
                    "expected_meta_revision": expected_meta_revision,
                },
                authority_grant_id=authority_grant_id,
            ),
        )

    async def get_operation(self, operation_id: str) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Operations.GetOperation",
            pub.GetOperationRequest(operation_id=operation_id),
            pub.ResourceResponse,
        )
        return _jcs_to_dict(response.resource_jcs)

    async def wait_operation(
        self, operation_id: str, *, timeout_s: float = 60.0
    ) -> dict[str, Any]:
        response = await self._call(
            "agent_meta.public.v1.Operations.WaitOperation",
            pub.WaitOperationRequest(operation_id=operation_id, wait_deadline_at_us=0),
            pub.ResourceResponse,
            deadline_us=int(timeout_s * 1_000_000),
        )
        return _jcs_to_dict(response.resource_jcs)

    # -- Graph ---------------------------------------------------------------
    async def why(
        self, entity_id: str, *, max_depth: int | None = None, cursor: str = ""
    ) -> dict[str, Any]:
        request = pub.WhyRequest(entity_id=entity_id, cursor=cursor)
        if max_depth:
            request.max_depth = max_depth
        response = await self._call("agent_meta.public.v1.Graph.Why", request, pub.WhyResponse)
        result = _jcs_to_dict(response.result_jcs)
        if response.next_cursor:
            result["next_cursor"] = response.next_cursor
        return result

    async def lineage(
        self,
        entity_id: str,
        *,
        direction: str = "DOWNSTREAM",
        limit: int | None = None,
        cursor: str = "",
    ) -> dict[str, Any]:
        request = pub.LineageRequest(entity_id=entity_id, direction=direction, cursor=cursor)
        if limit:
            request.limit = limit
        response = await self._call(
            "agent_meta.public.v1.Graph.Lineage", request, pub.LineageResponse
        )
        result = _jcs_to_dict(response.result_jcs)
        if response.next_cursor:
            result["next_cursor"] = response.next_cursor
        return result
