"""Internal durable Host -> certified fixed worker -> normalized terminal edge.

Profile/tokenizer/pricing and EffectIntent admission precede this edge. No public
profile selection or Managed isolation claim is made by constructing it.
"""

import secrets

from ..domain.canonical import now_us
from ..domain.errors import ErrorCode, StableError
from ..domain.execution_tokens import ExecutionTokenBinding, MAX_TOKEN_TTL_US, issue_execution_token
from ..domain.ids import new_uuid7
from ..ports.host_execution import HostCallValue
from ..ports.provider_transport import ProviderWorkerInterrupted


class ProviderHostCalls:
    def __init__(self, store, *, worker, trust, epoch_id, signer):
        self.store, self.worker, self.trust = store, worker, trust
        self.epoch_id, self.signer = epoch_id, signer

    async def invoke(self, *, task, invocation_id, request, required_permissions, normalize):
        # Signature bytes remain local control data. Only the verified audit is
        # persisted. Store authorization commits before the worker is called.
        if self.store.conn.in_transaction:
            raise StableError(code=ErrorCode.INTERNAL, message="Provider dispatch cannot span a Meta transaction")
        try:
            current = now_us()
            expires = min(current + MAX_TOKEN_TTL_US, self.trust.expires_at_us, request.deadline_at_us or current)
            if expires <= current:
                raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Provider dispatch deadline exceeded")
            binding = ExecutionTokenBinding(self.worker.session_id, task.realm_id, self.epoch_id, task.actor_id,
                task.root_action_id, "model.invoke", request.scope_hash, request.required_ceiling,
                frozenset(required_permissions), request.deadline_at_us)
            payload = {"token_version": 1, "token_id": new_uuid7(), "backend_session_id": binding.backend_session_id,
                "realm_id": binding.realm_id, "actor_id": binding.actor_id, "action_id": binding.action_id,
                "effect_kind": binding.effect_kind, "target_scope_hash": binding.target_scope_hash,
                "resource_ceiling": dict(binding.resource_ceiling), "issued_at_us": current,
                "expires_at_us": expires, "nonce": secrets.token_hex(16)}
            authorization = issue_execution_token(payload, service_principal_id=self.trust.service_principal_id, signer=self.signer)
            self.store.authorize_provider(task, invocation_id, request=request, binding=binding, authorization=authorization)
        except BaseException as exc:
            # No worker call has occurred in this process. Do not downgrade an
            # already-authorized attempt if a caller incorrectly invokes twice.
            if not isinstance(exc, StableError) or exc.code != ErrorCode.EXTERNAL_EFFECT_UNKNOWN:
                self.store.finish_invocation(invocation_id, error=exc.code if isinstance(exc, StableError) else ErrorCode.INTERNAL,
                    provider_outcome="NOT_SENT", require_undispatched=True)
            raise
        interrupted = None
        try:
            outcome = await self.worker.run(request, authorization=authorization, binding=binding)
        except ProviderWorkerInterrupted as exc:
            outcome, interrupted = exc.outcome, exc
        except BaseException as exc:
            # A port failure without a proven NOT_SENT observation is unknown.
            # The terminal commit is outside this handler: a failed commit must
            # never trigger a second attempt to write or send the request.
            from ..domain.provider_transport import ProviderHttpOutcome
            outcome = ProviderHttpOutcome("UNKNOWN", error_code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN)
            interrupted = exc if not isinstance(exc, Exception) else None
        finally:
            authorization = b""
        value = HostCallValue(error_code=outcome.error_code, raise_error=True) if outcome.error_code else None
        if value is None:
            try:
                value = normalize(outcome.content)
                if not isinstance(value, HostCallValue) or value.backend_result is not None:
                    raise ValueError("invalid normalized Provider terminal")
            except Exception:
                value = HostCallValue(error_code=ErrorCode.INVALID_RESULT, raise_error=True)
        receipt = self.store.finish_invocation(invocation_id, content=value.content, error=value.error_code,
            usage=dict(value.usage) if value.usage is not None else None,
            provider_outcome="CONFIRMED" if outcome.state == "RESPONSE" else outcome.state)
        if interrupted is not None:
            raise interrupted
        if receipt.get("provider_overrun"):
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Provider usage exceeded the admitted reservation")
        return value
