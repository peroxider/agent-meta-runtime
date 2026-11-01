"""Real InMemory activity edge for the trusted, zero-cost development Host.

The live Backend owns its handles. SQLite owns Invocation confirmation and the
ack outbox; ephemeral Backend state is never pickled/restored by this adapter.
"""

import asyncio
from dataclasses import replace
import secrets

from ..domain.canonical import canonical_json, now_us, sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.execution_tokens import ExecutionTokenBinding, issue_execution_token, MAX_TOKEN_TTL_US
from ..domain.ids import new_uuid7
from ..ports.execution import ExecutionOutcome
from ..ports.host_execution import HostCallValue
from ..protocols._v1 import execution_backend_pb2 as eb, transport_pb2 as tr
from .execution_memory.backend import InMemoryBackend


class MemoryHostActivities:
    def __init__(self, store, *, trust, epoch_id, signer):
        self.store, self.trust, self.epoch_id, self.signer = store, trust, epoch_id, signer
        self.backend = InMemoryBackend(executor=self._execute, authorize=self._authorize)
        self.session = None
        self._pending = {}

    async def start(self):
        self.session = await self.backend.negotiate(eb.ClientHello(
            supported=[tr.VersionRange(major=1, min_minor=0, max_minor=0)],
            client_instance_id=new_uuid7(), required_features=["activity"]))

    def _authorize(self, request):
        pending = self._pending.get(request.request_id)
        if pending is None or request.session_id != self.session.session_id or request.realm_id != pending["task"].realm_id or request.payload_hash != pending["payload_hash"] or bytes(request.payload_jcs) != pending["content"] or request.operation_kind != pending["operation_kind"]:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="unregistered Host activity request")
        audit = self.trust.verifier.verify(bytes(request.authority_token), request_id=request.request_id,
            request_payload_hash=request.payload_hash, binding=pending["binding"], now_us=now_us())
        pending["audit"] = self.store.authorize_backend(pending["task"], request.request_id, pending["capability_id"], audit)

    async def _execute(self, request):
        pending = self._pending[request.request_id]
        try:
            value = await pending["execute"]()
            if not isinstance(value, HostCallValue) or value.backend_result is not None:
                raise StableError(code=ErrorCode.INVALID_RESULT, message="invalid Host activity value")
        except Exception as exc:
            value = HostCallValue(error_code=exc.code if isinstance(exc, StableError) else ErrorCode.INTERNAL, raise_error=True)
        pending["value"] = value
        artifact = self.store.stage(value.content)["artifact_id"] if value.content is not None else ""
        return ExecutionOutcome("FAILED" if value.error_code else "SUCCEEDED",
            canonical_json(dict(value.usage)) if value.usage is not None else b"",
            canonical_json({"code": value.error_code, "raise_error": value.raise_error}) if value.error_code else b"", artifact)

    async def invoke(self, *, task, invocation_id, kind, capability_id, operation, content, execute):
        if self.session is None:
            raise StableError(code=ErrorCode.BACKEND_UNAVAILABLE, message="Host Backend session is unavailable")
        current = now_us()
        if self.trust.expires_at_us <= current:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="execution Service certificate has expired")
        expires = min(current + MAX_TOKEN_TTL_US, self.trust.expires_at_us,
            task.deadline_at_us if task.deadline_at_us is not None else current + MAX_TOKEN_TTL_US)
        if expires <= current:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Host execution authorization has expired")
        binding = ExecutionTokenBinding(self.session.session_id, task.realm_id, self.epoch_id, task.actor_id,
            task.root_action_id, "model.invoke" if kind == "MODEL" else "none",
            sha256_hex(canonical_json({"capability_id": capability_id, "operation_id": operation["operation_id"]})),
            {"calls": 1, "cost_microunits": 0}, frozenset({"model.invoke" if kind == "MODEL" else "capability.invoke", *operation["required_permissions"]}), task.deadline_at_us)
        payload = {"token_version": 1, "token_id": new_uuid7(), "backend_session_id": binding.backend_session_id,
            "realm_id": binding.realm_id, "actor_id": binding.actor_id, "action_id": binding.action_id,
            "effect_kind": binding.effect_kind, "target_scope_hash": binding.target_scope_hash,
            "resource_ceiling": dict(binding.resource_ceiling), "issued_at_us": current, "expires_at_us": expires,
            "nonce": secrets.token_hex(16)}
        request = eb.ExecutionRequest(session_id=self.session.session_id, realm_id=task.realm_id,
            request_id=invocation_id, operation_kind="test.model" if kind == "MODEL" else "test.capability",
            payload_hash=sha256_hex(content), payload_jcs=content, idempotency_class=operation["idempotency"],
            reversibility="REVERSIBLE", dedupe_scope=task.task_id, requested_retention_us=3_600_000_000,
            deadline_at_us=task.deadline_at_us or 0,
            authority_token=issue_execution_token(payload, service_principal_id=self.trust.service_principal_id, signer=self.signer))
        self._pending[invocation_id] = {"task": task, "binding": binding, "capability_id": capability_id,
            "content": content, "payload_hash": request.payload_hash, "operation_kind": request.operation_kind, "execute": execute}
        handle = None
        try:
            # submit currently has no suspension before returning the actual
            # handle; bind commits before the spawned callback can run.
            handle = await self.backend.submit(request)
            request.authority_token = b""
            receipt = self.store.bind_backend(invocation_id, handle=handle, payload_hash=request.payload_hash,
                audit=self._pending[invocation_id]["audit"])
            result = await self.backend.await_activity(handle, task.deadline_at_us or 0)
            value = self._pending[invocation_id].get("value")
            if value is None or result.effect_state_unknown:
                raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN, message="Host activity has no confirmed normalized outcome")
            artifact = "artifact://sha256/" + sha256_hex(value.content) if value.content is not None else ""
            error = canonical_json({"code": value.error_code, "raise_error": value.raise_error}) if value.error_code else b""
            expected_usage = canonical_json(dict(value.usage)) if value.usage is not None else b""
            if result.request_id != invocation_id or result.status != ("FAILED" if error else "SUCCEEDED") or result.result_artifact_id != artifact or bytes(result.error_jcs) != error or bytes(result.usage_jcs) != expected_usage or result.result_hash != sha256_hex(error or artifact.encode()):
                raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Host activity terminal differs from its normalized outcome")
            return replace(value, backend_result={**receipt, "terminal_status": result.status, "result_hash": result.result_hash,
                "result_artifact_id": artifact or None, "error_code": value.error_code, "raise_error": value.raise_error, "ack_state": "PENDING"})
        except BaseException:
            if handle is not None:
                # Cancellation is cooperative; a missing confirmation stays
                # UNKNOWN. No replay of an unfinished Meta Invocation follows.
                await self.backend.cancel(eb.CancelRequest(handle=handle, mode="FORCE", deadline_at_us=now_us() + 100_000))
                self.store.backend_unknown(invocation_id)
            raise
        finally:
            request.authority_token = b""
            self._pending.pop(invocation_id, None)

    async def acknowledge(self, item):
        payload = item["payload"]
        if self.store.check_ack(payload) != "PENDING":
            return
        if self.session is None or payload["session_id"] != self.session.session_id:
            self.store.record_ack(payload, acknowledged=False)
            return
        if self.store.conn.in_transaction:
            raise StableError(code=ErrorCode.INTERNAL, message="Backend ack cannot run in a Meta transaction")
        report = await self.backend.acknowledge_terminal(eb.TerminalAck(session_id=payload["session_id"],
            request_id=payload["request_id"], result_hash=payload["result_hash"]))
        if report.status != "ACKNOWLEDGED":
            raise StableError(code=ErrorCode.BACKEND_UNAVAILABLE, message="Backend terminal ack was not confirmed")
        self.store.record_ack(payload, acknowledged=True)

    async def close(self):
        if self.session is not None:
            await self.backend.close_session(self.session)
            self.session = None
