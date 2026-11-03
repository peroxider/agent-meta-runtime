"""Production AgentOS provider: the execution kernel bridge (§0–§2 of
docs/plans/agentos-execution-kernel-bridge.md).

``AgentOSProvider`` speaks the frozen eight-RPC backend session contract
(``agent_meta.execution_backend.v1``) and translates every call onto the
vendored ``agentos.kernel.v1`` ABI through an injected
:class:`~.kernel_transport.KernelTransport` (gRPC over UDS in production, an
in-process fake in the contract gate). Sessions, payload hashes, dedupe
scopes, retention and the UUIDv7↔UUIDv4 call mapping live in the bridge
ledger — the kernel has no session concept and none of those fields (§3 gap
table). ``authority_token`` bytes are enforcement-only: they are verified
through the injected verifier, reduced to a kernel ``claimed_principal_name``
and never logged, serialized, or forwarded (§1.3).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Callable

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7
from ...protocols._v1 import execution_backend_pb2 as eb
from ...protocols._kernel_v1 import common_pb2 as kcommon
from ...protocols._kernel_v1 import control_pb2 as kcontrol
from ...protocols._kernel_v1 import service_pb2 as kservice
from ...protocols._kernel_v1 import types_pb2 as ktypes
from ...protocols.backend_wire import build_envelope, error_to_rpc, payload_hash
from ..cas import FilesystemCas
from ..execution_portable.ledger import PortableRequestLedger
from .backend import parse_request_frame
from .kernel_transport import KernelRpcError, KernelTransport
from .mapping import (
    KERNEL_ABI_VERSION,
    activity_name,
    decode_ref,
    encode_ref,
    kernel_error_name,
    map_kernel_error,
    meta_request,
    process_name,
    realm_name,
    record_to_jcs,
    status_of,
    terminal_state,
    ts_to_us,
    usage_to_jcs,
)

__all__ = ["AgentOSProvider"]

#: Envelope trace keys ride the bridge into ``RequestMeta.trace_context``.
_TRACE: ContextVar[dict[str, str] | None] = ContextVar(
    "agentos_bridge_trace", default=None
)

_RESPONSE_TYPES: dict[str, Any] = {
    "Hello": kservice.HelloResponse,
    "GetKernelStatus": kservice.GetKernelStatusResponse,
    "CreateRealm": kservice.CreateRealmResponse,
    "InspectRealm": kservice.InspectRealmResponse,
    "SpawnProcess": kservice.SpawnProcessResponse,
    "InspectProcess": kservice.InspectProcessResponse,
    "SubmitActivity": kservice.SubmitActivityResponse,
    "InspectActivity": kservice.InspectActivityResponse,
    "WaitActivity": kservice.WaitActivityResponse,
    "CancelActivity": kservice.OperationResponse,
    "KillProcess": kservice.OperationResponse,
    "GetSnapshot": kservice.GetSnapshotResponse,
}

_CANCEL_REASON = "meta-runtime:cancel"


class AgentOSProvider:
    """The AgentOS execution kernel bridge behind the framed 8-RPC contract."""

    def __init__(
        self,
        data_dir: Path,
        *,
        transport: KernelTransport,
        backend_id: str = "backend://agentos-kernel",
        clock: Callable[[], int] | None = None,
        poll_interval_s: float = 0.05,
        default_grace_us: int = 2_000_000,
        snapshot_page_size: int = 256,
        token_verifier: Callable[[bytes], str] | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        (self._data_dir / "backend").mkdir(parents=True, exist_ok=True)
        self._kernel = transport
        self._backend_id = backend_id
        self._clock = clock or (lambda: time.time_ns() // 1000)
        self._ledger = PortableRequestLedger(
            str(self._data_dir / "backend" / "agentos-kernel.db"),
            backend_id=backend_id,
        )
        self._cas = FilesystemCas(self._data_dir)
        self._closed_sessions: set[str] = set()
        self._helloed = False
        self._poll_interval_s = poll_interval_s
        self._default_grace_us = default_grace_us
        self._snapshot_page_size = snapshot_page_size
        self._token_verifier = token_verifier

    # -- kernel call plumbing --------------------------------------------------
    async def _kernel_raw(
        self, method: str, request: Any, *, request_id: str | None = None
    ) -> Any:
        """One kernel RPC; records the UUIDv7↔UUIDv4 mapping when a request
        context exists (§3 gap 1). KernelRpcError propagates to callers that
        implement per-RPC tolerance (ALREADY_EXISTS races, wait deadlines)."""

        try:
            raw = await self._kernel.call(method, request.SerializeToString())
        except KernelRpcError:
            if request_id:
                self._record_kernel_call(request_id, method, request)
            raise
        if request_id:
            self._record_kernel_call(request_id, method, request)
        response = _RESPONSE_TYPES[method]()
        response.ParseFromString(raw)
        return response

    async def _kernel_call(
        self,
        method: str,
        request: Any,
        *,
        request_id: str | None = None,
        handle_context: bool = False,
    ) -> Any:
        """``_kernel_raw`` plus the §1.2 error mapping."""

        try:
            return await self._kernel_raw(method, request, request_id=request_id)
        except KernelRpcError as exc:
            raise self._map_kernel_error(exc, handle_context=handle_context) from exc

    def _map_kernel_error(
        self, exc: KernelRpcError, *, handle_context: bool = False
    ) -> StableError:
        return map_kernel_error(
            exc.code, exc.message, handle_context=handle_context, metadata=exc.metadata
        )

    def _record_kernel_call(self, request_id: str, method: str, request: Any) -> None:
        self._ledger.append_event(
            request_id,
            event_type="kernel_call",
            event={
                "method": method,
                "kernel_request_id": request.meta.request_id,
            },
            now_us=self._clock(),
        )

    def _meta(self, *, deadline_us: int = 0, principal: str = "") -> kcommon.RequestMeta:
        return meta_request(
            deadline_us=deadline_us, claimed_principal=principal, trace=_TRACE.get()
        )

    def _require_record(self, handle: eb.ExecutionHandle) -> dict[str, Any]:
        record = self._ledger.get(handle.request_id)
        if record is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="unknown handle",
                details={"request_id": handle.request_id},
            )
        return record

    def _enforce(self, request: eb.ExecutionRequest) -> str:
        """Verify the authority token, return its principal; never keep bytes."""

        token = bytes(request.authority_token)
        if not token:
            return ""
        if self._token_verifier is None:
            raise StableError(
                code=ErrorCode.AUTHORITY_DENIED,
                message="authority token presented but no verifier is configured",
            )
        return self._token_verifier(token)

    # -- Negotiate (§2.1) ---------------------------------------------------------
    async def negotiate(self, hello: eb.ClientHello) -> eb.BackendSession:
        if not any(int(rng.major) == 1 for rng in hello.supported):
            raise StableError(
                code=ErrorCode.CONTRACT_INCOMPATIBLE,
                message="client does not support kernel ABI major 1",
            )
        requested = list(
            dict.fromkeys([*hello.required_features, *hello.optional_features])
        )
        hello_resp = None
        if not self._helloed:
            # Hello must be the first RPC on the connection (§35.6).
            hello_resp = await self._kernel_raw(
                "Hello",
                kservice.HelloRequest(
                    supported_abi_versions=[KERNEL_ABI_VERSION],
                    requested_features=requested,
                ),
            )
            self._helloed = True
        status_resp = await self._kernel_raw(
            "GetKernelStatus",
            kservice.GetKernelStatusRequest(meta=self._meta()),
        )
        status = status_resp.status
        enabled = set(status.enabled_features)
        if hello_resp is not None:
            enabled |= set(hello_resp.enabled_features)
            selected = hello_resp.selected_abi_version
            instance = hello_resp.kernel_instance_id or status.kernel_instance_id
        else:
            selected = KERNEL_ABI_VERSION
            instance = status.kernel_instance_id
        minor = _parse_abi_minor(selected)
        missing = [f for f in hello.required_features if f not in enabled]
        if missing:
            raise StableError(
                code=ErrorCode.CONTRACT_INCOMPATIBLE,
                message="kernel does not enable required features",
                details={"missing": missing},
            )
        granted = sorted(
            (set(hello.required_features) | set(hello.optional_features)) & enabled
        )
        if instance:
            self._backend_id = f"backend://agentos-kernel/{instance}"
        established = ts_to_us(status_resp.meta.server_time) or self._clock()
        return eb.BackendSession(
            protocol_major=1,
            protocol_minor=minor,
            backend_id=self._backend_id,
            session_id=new_uuid7(),
            profile="MANAGED",
            features_jcs=canonical_json(granted),
            limits_jcs=canonical_json(_limits_of(status)),
            established_at_us=established,
        )

    def capabilities(self) -> dict[str, Any]:
        return {
            "backend_id": self._backend_id,
            "profile": "MANAGED",
            "features": {},  # honest until a Hello/GetKernelStatus populates it
        }

    # -- Submit (§2.2) --------------------------------------------------------------
    async def submit(self, request: eb.ExecutionRequest) -> eb.ExecutionHandle:
        if not request.request_id or not request.operation_kind:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="request_id and operation_kind are required",
            )
        if request.payload_hash != payload_hash(request.payload_jcs):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="payload_hash does not match payload_jcs",
            )
        try:
            uuid.UUID(request.request_id)
        except ValueError as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="request id must be a UUID"
            ) from exc
        if not request.session_id or request.session_id in self._closed_sessions:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="no open session"
            )
        principal = self._enforce(request)
        act_name = activity_name(request.request_id)
        record = self._ledger.submit(
            request_id=request.request_id,
            realm_id=request.realm_id,
            operation_kind=request.operation_kind,
            payload_hash=request.payload_hash,
            payload_jcs=bytes(request.payload_jcs),
            idempotency_class=request.idempotency_class or "NONE",
            reversibility=request.reversibility or "REVERSIBLE",
            request_relpath=f"agentos/{act_name}",
            now_us=self._clock(),
            requested_retention_us=request.requested_retention_us,
        )
        realm = await self._ensure_realm(
            request.realm_id, principal, request_id=request.request_id
        )
        host = process_name(realm)
        await self._ensure_process(
            realm, host, principal, request_id=request.request_id
        )
        activity = await self._submit_activity(
            record, request, realm, host, principal, act_name
        )
        return eb.ExecutionHandle(
            backend_id=self._backend_id,
            session_id=request.session_id,
            opaque_handle=encode_ref(activity.ref),
            incarnation=int(activity.ref.generation),
            expires_at_us=int(request.deadline_at_us),
            request_id=request.request_id,
        )

    async def _ensure_realm(
        self, realm_id: str, principal: str, *, request_id: str
    ) -> str:
        name = realm_name(realm_id)
        # The design doc says minimum_isolation "NAMESPACE"; the frozen ABI has
        # no such value — PROCESS_ISOLATED is the closest declared level.
        spec = kcontrol_spec_realm(name, principal)
        try:
            await self._kernel_raw(
                "CreateRealm",
                kservice.CreateRealmRequest(meta=self._meta(principal=principal), spec=spec),
                request_id=request_id,
            )
        except KernelRpcError as exc:
            if exc.code != kcommon.ALREADY_EXISTS:
                raise self._map_kernel_error(exc) from exc
            # Lazy-create race (§3 gap 6): tolerate ALREADY_EXISTS, confirm.
            try:
                await self._kernel_raw(
                    "InspectRealm",
                    kservice.InspectRealmRequest(
                        meta=self._meta(principal=principal), realm_name=name
                    ),
                    request_id=request_id,
                )
            except KernelRpcError as confirm_exc:
                raise self._map_kernel_error(confirm_exc) from confirm_exc
        return name

    async def _ensure_process(
        self, realm: str, host: str, principal: str, *, request_id: str
    ) -> None:
        spec = kcontrol_spec_process(realm, host, principal)
        try:
            await self._kernel_raw(
                "SpawnProcess",
                kservice.SpawnProcessRequest(meta=self._meta(principal=principal), spec=spec),
                request_id=request_id,
            )
        except KernelRpcError as exc:
            if exc.code != kcommon.ALREADY_EXISTS:
                raise self._map_kernel_error(exc) from exc
            try:
                await self._kernel_raw(
                    "InspectProcess",
                    kservice.InspectProcessRequest(
                        meta=self._meta(principal=principal), process_name=host
                    ),
                    request_id=request_id,
                )
            except KernelRpcError as confirm_exc:
                raise self._map_kernel_error(confirm_exc) from confirm_exc

    async def _submit_activity(
        self,
        record: dict[str, Any],
        request: eb.ExecutionRequest,
        realm: str,
        host: str,
        principal: str,
        act_name: str,
    ) -> Any:
        if not record["created"]:
            # Idempotent replay: same request id + same payload hash. If the
            # activity already landed, rebuild the handle from its current
            # ref; if it never did (crash before the kernel call), submit now.
            existing = await self._inspect_activity_or_none(
                act_name, principal, request_id=request.request_id
            )
            if existing is not None:
                return existing
        spec = kcontrol.ActivitySpec(
            requested_name=act_name,
            process_name=host,
            realm_name=realm,
            payload=kcommon.OpaquePayload(
                content_type="application/jcs+json",
                schema_ref=f"urn:agentos:schema:exec:{request.operation_kind}:v1",
                data=bytes(request.payload_jcs),
            ),
        )
        if request.deadline_at_us:
            spec.hard_deadline.FromMicroseconds(request.deadline_at_us)
        try:
            response = await self._kernel_raw(
                "SubmitActivity",
                kservice.SubmitActivityRequest(
                    meta=self._meta(deadline_us=request.deadline_at_us, principal=principal),
                    spec=spec,
                ),
                request_id=request.request_id,
            )
        except KernelRpcError as exc:
            if exc.code == kcommon.ALREADY_EXISTS:
                # Same hash (ledger-checked) → idempotent success path (§1.2).
                existing = await self._inspect_activity_or_none(
                    act_name, principal, request_id=request.request_id
                )
                if existing is not None:
                    return existing
            raise self._map_kernel_error(exc) from exc
        return response.activity

    async def _inspect_activity_or_none(
        self, act_name: str, principal: str, *, request_id: str
    ) -> Any | None:
        try:
            response = await self._kernel_raw(
                "InspectActivity",
                kservice.InspectActivityRequest(
                    meta=self._meta(principal=principal), activity_name=act_name
                ),
                request_id=request_id,
            )
        except KernelRpcError as exc:
            if exc.code == kcommon.NOT_FOUND:
                return None
            raise self._map_kernel_error(exc) from exc
        return response.activity

    # -- Await (§2.3) ------------------------------------------------------------
    async def await_activity(
        self, handle: eb.ExecutionHandle, deadline_at_us: int
    ) -> eb.ExecutionResult:
        self._require_record(handle)
        name, generation, _revision = decode_ref(handle.opaque_handle)
        try:
            response = await self._kernel_raw(
                "WaitActivity",
                kservice.WaitActivityRequest(
                    meta=self._meta(deadline_us=deadline_at_us),
                    activity_name=name,
                    expected_generation=generation,
                ),
                request_id=handle.request_id,
            )
        except KernelRpcError as exc:
            if exc.code == kcommon.DEADLINE_EXCEEDED:
                # A wait deadline is not an execution failure: the activity
                # keeps running and Inspect/Await stay available (§2.3).
                return eb.ExecutionResult(
                    status="RUNNING",
                    request_id=handle.request_id,
                    effect_state_unknown=False,
                )
            raise self._map_kernel_error(exc, handle_context=True) from exc
        record = response.activity
        if terminal_state(record.state) and record.HasField("result"):
            return await self._terminal_result(handle.request_id, record)
        return eb.ExecutionResult(
            status=status_of(record.state),
            request_id=handle.request_id,
            effect_state_unknown=False,
        )

    # -- terminal result construction (§2.3 ActivityResult → ExecutionResult) ------
    async def _build_terminal_result(
        self, request_id: str, record: Any
    ) -> eb.ExecutionResult:
        """Project a kernel terminal ActivityResult without ledger side effects."""

        result = record.result
        res = eb.ExecutionResult(
            status=status_of(record.state),
            request_id=request_id,
            completed_at_us=ts_to_us(result.completed_at) or self._clock(),
            effect_state_unknown=False,
        )
        exit_code = int(result.exit_code) if result.HasField("exit_code") else None
        res.usage_jcs = (
            usage_to_jcs(result.usage, exit_code=exit_code)
            if result.HasField("usage")
            else b""
        )
        outcome_bytes = b""
        if record.state == ktypes.ACTIVITY_STATE_KILLED:
            res.error_jcs = canonical_json(
                {
                    "code": "FAILED",
                    "kernel_code": "ACTIVITY_STATE_KILLED",
                    "message": "activity killed by the kernel",
                }
            )
            outcome_bytes = bytes(res.error_jcs)
        elif result.HasField("error"):
            kerr = result.error
            res.error_jcs = canonical_json(
                {
                    "code": map_kernel_error(int(kerr.code), kerr.message).code,
                    "kernel_code": kernel_error_name(int(kerr.code)),
                    "message": kerr.message,
                }
            )
            outcome_bytes = bytes(res.error_jcs)
        elif result.payload.data:
            data = bytes(result.payload.data)
            res.result_artifact_id = self._cas.put(data)
            outcome_bytes = data
        res.result_hash = sha256_hex(outcome_bytes)
        return res

    async def _terminal_result(self, request_id: str, record: Any) -> eb.ExecutionResult:
        res = await self._build_terminal_result(request_id, record)
        self._ledger.mark_terminal(
            request_id,
            result_hash=res.result_hash,
            result_jcs=canonical_json(_result_summary(res)),
            effect_state_unknown=False,
            now_us=self._clock(),
        )
        return res

    # -- Inspect (§2.5) ------------------------------------------------------------
    async def inspect(self, handle: eb.ExecutionHandle) -> eb.ExecutionSnapshot:
        self._require_record(handle)
        name, _generation, _revision = decode_ref(handle.opaque_handle)
        try:
            response = await self._kernel_raw(
                "InspectActivity",
                kservice.InspectActivityRequest(meta=self._meta(), activity_name=name),
                request_id=handle.request_id,
            )
        except KernelRpcError as exc:
            raise self._map_kernel_error(exc, handle_context=True) from exc
        record = response.activity
        snapshot = eb.ExecutionSnapshot(
            handle=eb.ExecutionHandle(
                backend_id=self._backend_id,
                session_id=handle.session_id,
                opaque_handle=encode_ref(record.ref),
                incarnation=int(record.ref.generation),
                expires_at_us=handle.expires_at_us,
                request_id=handle.request_id,
            ),
            status=status_of(record.state),
            observed_at_us=ts_to_us(response.meta.server_time) or self._clock(),
        )
        if terminal_state(record.state) and record.HasField("result"):
            snapshot.terminal.CopyFrom(await self._terminal_result(handle.request_id, record))
        return snapshot

    # -- Cancel (§2.4) ----------------------------------------------------------------
    async def cancel(self, request: eb.CancelRequest) -> eb.CancelReport:
        if (request.mode or "GRACEFUL") not in ("GRACEFUL", "KILL"):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="mode must be GRACEFUL or KILL"
            )
        self._require_record(request.handle)
        name, _generation, _revision = decode_ref(request.handle.opaque_handle)
        current = await self._inspect_for_handle(name, request.handle.request_id)
        details: dict[str, Any] = {}
        if not terminal_state(current.state):
            if current.state not in (
                ktypes.ACTIVITY_STATE_CANCELLING,
                ktypes.ACTIVITY_STATE_KILLING,
            ):
                operation = await self._cancel_activity(
                    current, request.handle.request_id
                )
                details["cancel"] = json.loads(record_to_jcs(operation))
            else:
                details["cancel"] = {"skipped": "already_cancelling"}
            post = await self._inspect_for_handle(name, request.handle.request_id)
            if not terminal_state(post.state) and (request.mode or "GRACEFUL") == "KILL":
                post = await self._kill_ladder(
                    post, request.handle.request_id, request.deadline_at_us, details
                )
        else:
            post = current
        return await self._cancel_report(request.handle.request_id, post, details)

    async def _cancel_report(
        self, request_id: str, record: Any, details: dict[str, Any]
    ) -> eb.CancelReport:
        details_jcs = canonical_json(details)
        if terminal_state(record.state) and record.HasField("result"):
            result = await self._terminal_result(request_id, record)
            return eb.CancelReport(
                status=result.status, terminal_confirmed=True, details_jcs=details_jcs
            )
        return eb.CancelReport(
            status=status_of(record.state),
            terminal_confirmed=terminal_state(record.state),
            details_jcs=details_jcs,
        )

    async def _kill_ladder(
        self,
        record: Any,
        request_id: str,
        deadline_at_us: int,
        details: dict[str, Any],
    ) -> Any:
        """KILL mode: wait out the cancel ladder, then KillProcess (§2.4)."""

        horizon = deadline_at_us or self._clock() + self._default_grace_us
        while not terminal_state(record.state) and self._clock() < horizon:
            await asyncio.sleep(self._poll_interval_s)
            record = await self._inspect_for_handle(
                record.ref.name, request_id
            )
        if terminal_state(record.state):
            return record
        try:
            operation = await self._kernel_call(
                "KillProcess",
                kservice.KillProcessRequest(
                    meta=self._meta(),
                    process_name=record.process_name,
                    reason=_CANCEL_REASON,
                ),
                request_id=request_id,
            )
            details["kill"] = json.loads(record_to_jcs(operation.operation))
        except StableError as exc:
            if exc.code != ErrorCode.NOT_FOUND:
                raise
            # Nothing left to kill (host already gone); report as observed.
            details["kill"] = {"skipped": "process_not_found"}
        return await self._inspect_for_handle(record.ref.name, request_id)

    async def _inspect_for_handle(self, name: str, request_id: str) -> Any:
        try:
            response = await self._kernel_raw(
                "InspectActivity",
                kservice.InspectActivityRequest(meta=self._meta(), activity_name=name),
                request_id=request_id,
            )
        except KernelRpcError as exc:
            raise self._map_kernel_error(exc, handle_context=True) from exc
        return response.activity

    async def _cancel_activity(self, record: Any, request_id: str) -> Any:
        # The kernel's CAS fields double as optimistic concurrency (§2.4).
        try:
            response = await self._kernel_raw(
                "CancelActivity",
                kservice.CancelActivityRequest(
                    meta=self._meta(),
                    activity_name=record.ref.name,
                    expected_generation=int(record.ref.generation),
                    expected_revision=int(record.ref.revision),
                    reason=_CANCEL_REASON,
                ),
                request_id=request_id,
            )
        except KernelRpcError as exc:
            raise self._map_kernel_error(exc, handle_context=True) from exc
        return response.operation

    # -- Reconcile (§2.6) -----------------------------------------------------------------
    async def reconcile(self, request: eb.ReconcileRequest) -> eb.ReconcileReport:
        report = eb.ReconcileReport()
        activities, observed_at_us = await self._snapshot_activities()
        report.observed_at_us = observed_at_us or self._clock()
        for known in request.known:
            record = self._ledger.get(known.request_id)
            if record is None or record["realm_id"] != request.realm_id:
                continue
            name, _generation, _revision = decode_ref(known.handle.opaque_handle)
            record_pb = activities.get(name)
            if record_pb is None:
                # Never landed or past kernel retention: orphan (§2.6).
                orphan = report.orphans.add()
                orphan.handle.CopyFrom(known.handle)
                orphan.request_id = known.request_id
                orphan.payload_hash = known.payload_hash or record["payload_hash"]
                orphan.recommended_action = "resubmit"
                continue
            binding = report.bindings.add()
            binding.known.CopyFrom(known)
            if terminal_state(record_pb.state) and record_pb.HasField("result"):
                # Compare the projection against the ledger before committing
                # it, so a divergence raises INTEGRITY_ERROR without a
                # REVISION_CONFLICT masking it (§2.6).
                result = await self._build_terminal_result(known.request_id, record_pb)
                stored = self._ledger.get(known.request_id)["result_hash"]
                if stored is not None and stored != result.result_hash:
                    raise StableError(
                        code=ErrorCode.INTEGRITY_ERROR,
                        message="reconciled terminal result hash diverges from the ledger",
                        details={"request_id": known.request_id},
                    )
                if stored is None:
                    self._ledger.mark_terminal(
                        known.request_id,
                        result_hash=result.result_hash,
                        result_jcs=canonical_json(_result_summary(result)),
                        effect_state_unknown=False,
                        now_us=self._clock(),
                    )
                binding.status = "TERMINAL"
                binding.terminal.CopyFrom(result)
            else:
                binding.status = status_of(record_pb.state)
                # Kernel restart advances the generation → new incarnation.
                binding.renewed_handle.CopyFrom(
                    eb.ExecutionHandle(
                        backend_id=self._backend_id,
                        session_id=known.handle.session_id,
                        opaque_handle=encode_ref(record_pb.ref),
                        incarnation=int(record_pb.ref.generation),
                        expires_at_us=known.handle.expires_at_us,
                        request_id=known.request_id,
                    )
                )
        return report

    async def _snapshot_activities(self) -> tuple[dict[str, Any], int]:
        activities: dict[str, Any] = {}
        observed_at_us = 0
        page_token = ""
        while True:
            response = await self._kernel_call(
                "GetSnapshot",
                kservice.GetSnapshotRequest(
                    meta=self._meta(),
                    scope=kcommon.ObjectScope(kind="activity"),
                    page_size=self._snapshot_page_size,
                    page_token=page_token,
                ),
            )
            for record in response.snapshot.activities:
                activities[record.ref.name] = record
            observed_at_us = ts_to_us(response.meta.server_time) or observed_at_us
            page_token = response.next_page_token
            if not page_token:
                return activities, observed_at_us

    # -- AcknowledgeTerminal (§2.7) ----------------------------------------------------------
    async def acknowledge_terminal(self, request: eb.TerminalAck) -> eb.AckReport:
        record = self._ledger.get(request.request_id)
        if record is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"unknown request {request.request_id}",
            )
        if record["state"] != "TERMINAL":
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="request not terminal"
            )
        if request.result_hash != record["result_hash"]:
            raise StableError(
                code=ErrorCode.INTEGRITY_ERROR,
                message="acknowledged result hash diverges from the ledger",
                details={"request_id": request.request_id},
            )
        # Bridge-side retention: the requested window counted from the ack
        # (§2.7); the kernel record stays in its SQLite snapshot untouched.
        retention = max(int(record["retained_until_us"]) - int(record["created_at_us"]), 0)
        retained = self._ledger.acknowledge_terminal(
            request.request_id,
            result_hash=request.result_hash,
            retained_until_us=self._clock() + retention,
            now_us=self._clock(),
        )
        return eb.AckReport(status="ACKED", retained_until_us=retained)

    # -- CloseSession (§2.8) -----------------------------------------------------------------
    async def close_session(self, session: eb.BackendSession) -> eb.CloseReport:
        # Advisory only: in-flight kernel activities keep running (§2.8).
        self._closed_sessions.add(session.session_id)
        return eb.CloseReport(
            status="CLOSED", session_id=session.session_id, closed_at_us=self._clock()
        )

    # -- framed contract (same position as AgentOSFakeProvider) -------------------------------
    async def dispatch(self, raw: bytes) -> bytes:
        """Parse one serialized request envelope, answer with one response."""

        request, operation, message, error = parse_request_frame(raw)
        if error is not None:
            return build_envelope(
                method=request.method,
                error=error_to_rpc(error, correlation_id=request.request_id),
                is_response=True,
                request_id=request.request_id,
            ).SerializeToString()
        token = _TRACE.set(dict(request.trace) if request.trace else None)
        try:
            if operation == "await_activity":
                result = await self.await_activity(message, request.deadline_at_us)
            else:
                result = await getattr(self, operation)(message)
            return build_envelope(
                method=request.method,
                payload=result.SerializeToString(),
                is_response=True,
                request_id=request.request_id,
            ).SerializeToString()
        except StableError as exc:
            return build_envelope(
                method=request.method,
                error=error_to_rpc(exc, correlation_id=request.request_id),
                is_response=True,
                request_id=request.request_id,
            ).SerializeToString()
        finally:
            _TRACE.reset(token)


# -- module-level spec builders (keep the provider body readable) -------------------

def kcontrol_spec_realm(name: str, principal: str) -> Any:
    return kcontrol.RealmSpec(
        requested_name=name,
        principal_name=principal,
        adapter_kind="linux",
        minimum_isolation=ktypes.ISOLATION_LEVEL_PROCESS_ISOLATED,
    )


def kcontrol_spec_process(realm: str, host: str, principal: str) -> Any:
    return kcontrol.ProcessSpec(
        requested_name=host,
        principal_name=principal,
        realm_name=realm,
        adapter_kind="linux",
        entrypoint=ktypes.WorkloadEntrypoint(
            execution_mode=ktypes.EXECUTION_MODE_MULTIPLEXED_SERVICE,
            completion_kind=ktypes.COMPLETION_KIND_PROCESS_EXIT,
        ),
        restart_policy=ktypes.RestartPolicy(mode=ktypes.RESTART_MODE_ALWAYS),
    )


def _parse_abi_minor(selected: str) -> int:
    if selected == KERNEL_ABI_VERSION:
        return 0
    prefix = KERNEL_ABI_VERSION + "."
    if selected.startswith(prefix) and selected[len(prefix) :].isdigit():
        return int(selected[len(prefix) :])
    raise StableError(
        code=ErrorCode.CONTRACT_INCOMPATIBLE,
        message=f"kernel selected an unparseable ABI version: {selected!r}",
    )


def _limits_of(status: Any) -> dict[str, Any]:
    """Honest resource inventory from GetKernelStatus (§2.1).

    The kernel status carries no quota fields; the bridge reports exactly
    what it declares and invents nothing.
    """

    return {
        "kernel_state": ktypes.KernelState.Name(status.state),
        "server_version": status.server_version,
        "schema_version": int(status.schema_version),
        "global_revision": int(status.global_revision),
        "enabled_features": list(status.enabled_features),
    }


def _result_summary(res: eb.ExecutionResult) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "status": res.status,
        "request_id": res.request_id,
        "result_hash": res.result_hash,
        "completed_at_us": int(res.completed_at_us),
        "effect_state_unknown": bool(res.effect_state_unknown),
    }
    outcome = res.WhichOneof("outcome")
    if outcome == "result_artifact_id":
        summary["result_artifact_id"] = res.result_artifact_id
    elif outcome == "error_jcs":
        summary["error_jcs"] = bytes(res.error_jcs).decode("utf-8")
    return summary
