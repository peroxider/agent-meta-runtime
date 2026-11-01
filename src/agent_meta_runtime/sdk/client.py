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

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from ..domain.canonical import canonical_json, now_us
from ..domain.command_policy import COMMAND_METHODS
from ..domain.provider_configuration import configuration_payload
from ..domain.envelope import CommandEnvelope
from ..domain.errors import ErrorCode, StableError
from ..domain.ids import new_uuid7
from ..domain.task_submission import parse_task_submission
from ..domain.principal_contract import principal_registration, delegation_payload, revocation_payload
from ..protocols._v1 import public_pb2 as pub
from .commands import CommandAuthority, decode_command, encode_command, sign_command

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


def _wait_deadlines(timeout_s: float) -> tuple[int, int]:
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not math.isfinite(timeout_s) or timeout_s < 0:
        raise ValueError("wait timeout must be a finite non-negative number")
    # The server's single Wait cap is 60s. Leave the transport one second to
    # return a nonterminal snapshot rather than racing the Wait timeout.
    wait_at = now_us() + int(min(timeout_s, 60) * 1_000_000)
    return wait_at, wait_at + 1_000_000


class AgentMetaClient:
    """Typed facade over the Public API v1 method registry."""

    def __init__(self, transport: Transport, *, authority: CommandAuthority | None = None) -> None:
        self._transport = transport
        self._authority = authority

    async def aclose(self) -> None:
        await self._transport.close()

    @property
    def server_instance_id(self) -> str | None:
        """Authenticated Hello identity when supplied by the local transport."""
        return getattr(self._transport, "server_instance_id", None)

    async def stop_runtime(self, *, realm_id: str, actor_id: str,
                           instance_id: str | None = None, reason_code: str = "operator_stop",
                           authority_grant_id: str | None = None) -> MutationResult:
        """Request shutdown of one exact daemon incarnation (Public API 1.1).

        STOPPING acknowledges durable admission, not completion of OS shutdown.
        """
        instance_id = instance_id or self.server_instance_id
        if not isinstance(instance_id, str) or not instance_id or len(instance_id) > 128:
            raise ValueError("stop requires a daemon instance identity from Hello")
        negotiated = getattr(self._transport, "negotiated_version", None)
        if negotiated is not None and negotiated < (1, 1):
            from ..domain.errors import ErrorCode, StableError
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="Runtime.Stop requires Public API 1.1")
        return await self.execute_command("agent_meta.public.v1.Runtime.Stop", self.build_envelope_jcs(
            realm_id=realm_id, actor_id=actor_id, payload_type="runtime.stop/v1",
            payload={"instance_id": instance_id, "reason_code": reason_code},
            authority_grant_id=authority_grant_id,
        ))

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
        command_id: str | None = None,
    ) -> str:
        """Canonical CommandEnvelope JCS for one mutation (§41.46).

        Also used by the CLI ``--dry-run`` path, which validates the plan
        without sending it.
        """

        if self._authority is not None and actor_id == self._authority.actor_id and authority_grant_id is None:
            authority_grant_id = self._authority.authority_grant_id
        envelope = CommandEnvelope(
            command_id=command_id or "task://" + new_uuid7(),
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
        if self._authority is not None and actor_id == self._authority.actor_id:
            envelope = sign_command(envelope, self._authority)
        return encode_command(envelope)

    async def execute_command(self, method: str, envelope_jcs: str, *, deadline_us: int | None = None) -> MutationResult:
        """Send an already prepared command verbatim; never generate a new ID.

        Persist method + full envelope before sending when recovery is needed.
        Recovery must replay that exact representation, not a convenience method.
        """
        envelope = decode_command(envelope_jcs)
        if method not in COMMAND_METHODS or COMMAND_METHODS[method][0] != envelope.payload_type:
            raise ValueError("command method/payload type differs from the public registry")
        return await self._mutate(method, envelope_jcs, deadline_us=deadline_us)

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

    async def get_view(self, meta_revision: int | None = None, *, include_backend: bool = False) -> dict[str, Any]:
        request = pub.GetViewRequest(include_backend=include_backend)
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

    # -- ordinary Authority ---------------------------------------------------
    async def create_principal(self, *, realm_id: str, actor_id: str, kind: str, public_key: bytes,
                               principal_id: str | None = None, authority_grant_id: str | None = None) -> MutationResult:
        if not isinstance(public_key, bytes):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="public key must be raw Ed25519 bytes")
        payload = {"kind": kind, "public_key_hex": public_key.hex()}
        if principal_id is not None:
            payload["principal_id"] = principal_id
        principal_registration(payload)
        return await self._mutate("agent_meta.public.v1.Authority.CreatePrincipal", self.build_envelope_jcs(
            realm_id=realm_id, actor_id=actor_id, payload_type="authority.principal.create/v1", payload=payload,
            authority_grant_id=authority_grant_id))

    async def delegate_authority(self, *, realm_id: str, actor_id: str, subject_id: str, permissions: Sequence[str],
                                 scope: Mapping[str, Any], constraints: Mapping[str, Any] | None = None,
                                 delegable: bool = False, authority_grant_id: str | None = None) -> MutationResult:
        if (not isinstance(scope, Mapping) or constraints is not None and not isinstance(constraints, Mapping)
                or isinstance(permissions, (str, bytes)) or not isinstance(permissions, Sequence)):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="delegation requires an object scope/constraints and a permission sequence")
        try:
            payload = {"subject_id": subject_id, "permissions": sorted(set(permissions)), "scope": dict(scope),
                "constraints": dict(constraints) if constraints is not None else {}, "delegable": delegable}
        except (ValueError, TypeError) as exc:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid delegation arguments") from exc
        delegation_payload(payload, realm_id=realm_id)
        return await self._mutate("agent_meta.public.v1.Authority.Delegate", self.build_envelope_jcs(
            realm_id=realm_id, actor_id=actor_id, payload_type="authority.delegate/v1", payload=payload,
            authority_grant_id=authority_grant_id))

    async def revoke_authority(self, *, realm_id: str, actor_id: str, grant_id: str,
                               reason_code: str = "operator_revoke", authority_grant_id: str | None = None) -> MutationResult:
        payload = {"grant_id": grant_id, "reason_code": reason_code}
        revocation_payload(payload)
        return await self._mutate("agent_meta.public.v1.Authority.Revoke", self.build_envelope_jcs(
            realm_id=realm_id, actor_id=actor_id, payload_type="authority.revoke/v1", payload=payload,
            authority_grant_id=authority_grant_id))

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
        causal_parent_action_id: str | None = None,
    ) -> TaskHandle:
        payload: dict[str, Any] = {"input_artifact_id": input_artifact_id}
        if budget is not None:
            payload["budget"] = dict(budget) if isinstance(budget, Mapping) else budget
        if deadline_at_us is not None:
            payload["deadline_at_us"] = deadline_at_us
        parse_task_submission(payload)
        result = await self._mutate(
            "agent_meta.public.v1.Task.Submit",
            self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="task.submit/v1",
                payload=payload,
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
                causal_parent_action_id=causal_parent_action_id,
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

    async def get_task_execution(self, task_id: str) -> dict[str, Any]:
        """Read bounded durable invocation/projection metadata (Public API 1.2)."""
        response = await self._call("agent_meta.public.v1.Task.GetExecution",
            pub.GetTaskRequest(task_id=task_id), pub.ResourceResponse)
        return _jcs_to_dict(response.resource_jcs)

    async def get_task_trace(self, task_id: str) -> dict[str, Any]:
        """Bounded persisted Action/Fact state metadata (Public API 1.5)."""
        response = await self._call("agent_meta.public.v1.Task.GetTrace", pub.GetTaskRequest(task_id=task_id), pub.ResourceResponse)
        return _jcs_to_dict(response.resource_jcs)

    async def wait_task(
        self, task_id: str, *, timeout_s: float = 60.0
    ) -> tuple[dict[str, Any], bool]:
        """Wait for terminal state; ``(resource, terminal)`` — timeout is not an error."""

        wait_at, rpc_at = _wait_deadlines(timeout_s)
        response = await self._call(
            "agent_meta.public.v1.Task.Wait",
            pub.WaitTaskRequest(task_id=task_id, wait_deadline_at_us=wait_at),
            pub.TaskWaitResponse,
            deadline_us=rpc_at,
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

    async def get_artifact_content(self, artifact_id: str) -> bytes:
        """Read/hash-verify ordinary content up to 1 MiB (Public API 1.3)."""
        response = await self._call("agent_meta.public.v1.Artifact.GetContent",
            pub.GetArtifactRequest(artifact_id=artifact_id), pub.ResourceResponse)
        try:
            if len(response.resource_jcs) > 2 * 1024 * 1024 + 4096:
                raise ValueError("content response exceeds ceiling")
            value = json.loads(response.resource_jcs)
            if not isinstance(value, dict) or canonical_json(value) != response.resource_jcs:
                raise ValueError("content response is not a canonical object")
            if value.get("resource_type") != "artifact-content/v1" or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
                raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="unsupported Artifact content response schema")
            if value.get("artifact_id") != artifact_id or not all(isinstance(value.get(key), str) for key in ("kind", "media_type")) or type(value.get("size_bytes")) is not int or not 0 <= value["size_bytes"] <= 1024 * 1024:
                raise ValueError("invalid content identity or size")
            if not isinstance(value.get("content_hex"), str) or len(value["content_hex"]) != 2 * value["size_bytes"]:
                raise ValueError("invalid content encoding")
            content = bytes.fromhex(value["content_hex"])
            if content.hex() != value["content_hex"] or len(content) != value["size_bytes"] or "artifact://sha256/" + hashlib.sha256(content).hexdigest() != artifact_id:
                raise ValueError("content hash mismatch")
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Artifact content response failed verification") from exc
        return content

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
        expected_serving_revision: int | None = None,
    ) -> MutationResult:
        envelope = await self.prepare_harness_activation(
            realm_id=realm_id, actor_id=actor_id, harness_id=harness_id,
            composition_body_artifact_id=composition_body_artifact_id,
            grant_requests=grant_requests, plan_hash=plan_hash, grant_request_hash=grant_request_hash,
            authority_grant_id=authority_grant_id, expected_meta_revision=expected_meta_revision,
            expected_serving_revision=expected_serving_revision,
        )
        return await self.execute_command("agent_meta.public.v1.Harness.Activate", envelope)

    async def prepare_harness_activation(
        self, *, realm_id: str, actor_id: str, harness_id: str,
        composition_body_artifact_id: str, grant_requests: list[dict[str, Any]] | None = None,
        plan_hash: str = "", grant_request_hash: str = "",
        authority_grant_id: str | None = None, expected_meta_revision: int | None = None,
        expected_serving_revision: int | None = None,
    ) -> str:
        """Read/validate and sign an exact activation plan without submitting it.

        Explicit hashes/revisions are preserved; stale plans fail on submission.
        Persist the returned bytes to recover a lost response with execute_command.
        """
        if not plan_hash:
            installation = await self.get_harness(harness_id)
            report = await self.validate_harness_package(installation["manifest_artifact_id"])
            if not report["valid"]:
                from ..domain.errors import ErrorCode, StableError
                raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="activation package validation failed", details=report)
            plan_hash = report["plan_hash"]
        requests = list(grant_requests or [])
        if not grant_request_hash:
            grant_request_hash = hashlib.sha256(canonical_json(requests)).hexdigest()
        if expected_meta_revision is None or expected_serving_revision is None:
            view = await self.get_view()
            if view["realm_id"] != realm_id:
                raise ValueError("activation Realm differs from endpoint")
            if expected_meta_revision is None:
                expected_meta_revision = view["meta_revision"]
            if expected_serving_revision is None:
                expected_serving_revision = view["serving_revision"]
        return self.build_envelope_jcs(
                realm_id=realm_id,
                actor_id=actor_id,
                payload_type="harness.activate/v1",
                payload={
                    "harness_id": harness_id,
                    "composition_body_artifact_id": composition_body_artifact_id,
                    "grant_requests": requests,
                    "plan_hash": plan_hash,
                    "grant_request_hash": grant_request_hash,
                    "expected_serving_revision": expected_serving_revision,
                },
                authority_grant_id=authority_grant_id,
                expected_meta_revision=expected_meta_revision,
        )

    async def prepare_harness_provider_configuration(self, *, realm_id: str, actor_id: str, harness_id: str,
            capability_id: str, profile_artifact_id: str, credential_handle: str, enabled: bool=True,
            expected_configuration_revision: int | None=None, expected_meta_revision: int | None=None,
            authority_grant_id: str | None=None) -> str:
        """Sign a reviewable, secretless installation/profile/handle binding."""
        payload=configuration_payload({'harness_id':harness_id,'capability_id':capability_id,'profile_artifact_id':profile_artifact_id,
            'credential_handle':credential_handle,'enabled':enabled,'expected_configuration_revision':expected_configuration_revision if expected_configuration_revision is not None else 0})
        if expected_configuration_revision is None:
            installation=await self.get_harness(harness_id)
            old=installation.get('provider_configuration')
            expected_configuration_revision=old['configuration_revision'] if old else 0
        if expected_meta_revision is None:
            view=await self.get_view()
            if view['realm_id']!=realm_id:
                raise ValueError('Provider configuration Realm differs from endpoint')
            expected_meta_revision=view['meta_revision']
        payload['expected_configuration_revision']=expected_configuration_revision
        return self.build_envelope_jcs(realm_id=realm_id,actor_id=actor_id,payload_type='harness.configure-provider/v1',
            payload=payload,
            authority_grant_id=authority_grant_id,expected_meta_revision=expected_meta_revision)

    async def validate_harness_provider_configuration(self, envelope_jcs: str) -> dict[str, Any]:
        """Read-only validation of a signed binding; no command/use claim."""
        response=await self._call('agent_meta.public.v1.Harness.ValidateProviderConfiguration',
            pub.CommandRequest(command_envelope_jcs=envelope_jcs.encode('utf-8')),pub.ResourceResponse)
        return _jcs_to_dict(response.resource_jcs)

    async def configure_harness_provider(self, *, realm_id: str, actor_id: str, harness_id: str,
            capability_id: str, profile_artifact_id: str, credential_handle: str, enabled: bool=True,
            expected_configuration_revision: int | None=None, expected_meta_revision: int | None=None,
            authority_grant_id: str | None=None) -> MutationResult:
        envelope=await self.prepare_harness_provider_configuration(realm_id=realm_id,actor_id=actor_id,harness_id=harness_id,
            capability_id=capability_id,profile_artifact_id=profile_artifact_id,credential_handle=credential_handle,enabled=enabled,
            expected_configuration_revision=expected_configuration_revision,expected_meta_revision=expected_meta_revision,
            authority_grant_id=authority_grant_id)
        return await self.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)

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
        wait_at, rpc_at = _wait_deadlines(timeout_s)
        response = await self._call(
            "agent_meta.public.v1.Evolution.WaitExperiment",
            pub.WaitExperimentRequest(experiment_id=experiment_id, wait_deadline_at_us=wait_at),
            pub.TaskWaitResponse,
            deadline_us=rpc_at,
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
        wait_at, rpc_at = _wait_deadlines(timeout_s)
        response = await self._call(
            "agent_meta.public.v1.Operations.WaitOperation",
            pub.WaitOperationRequest(operation_id=operation_id, wait_deadline_at_us=wait_at),
            pub.ResourceResponse,
            deadline_us=rpc_at,
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
