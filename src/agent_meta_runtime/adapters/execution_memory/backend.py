"""InMemory contract backend with injectable durable fake state (§37.0.3,
§41.48.2).

The production InMemory profile reports ``persistent_idempotency=EMULATED``
honestly and only accepts effect-free test workloads (``test.*`` operation
kinds with non-irreversible reversibility). ``DurableFakeBackendState`` is the
injection point contract tests use to simulate restart: its serialized bytes
survive across backend instances, proving idempotency and terminal-commit
rules hold against restored state.
"""

from __future__ import annotations

import asyncio
import pickle
import time
import uuid
from typing import Any, Awaitable, Callable

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...ports.execution import ExecutionOutcome
from ...protocols._v1 import execution_backend_pb2 as eb
from ...protocols.backend_wire import (
    AuthorityToken,
    negotiate_version,
    payload_hash,
    select_features,
)

__all__ = ["DurableFakeBackendState", "InMemoryBackend", "TERMINAL_STATUSES"]

TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})

#: Feature profile of the production InMemory backend: emulation is reported,
#: never claimed as real isolation or quota (§37.0.2, §41.48.4).
INMEMORY_FEATURES: dict[str, str] = {
    "process": "SUPPORTED",
    "activity": "SUPPORTED",
    "channel": "SUPPORTED",
    "persistent_idempotency": "EMULATED",
    "isolated_realm": "UNSUPPORTED",
    "network_isolation": "UNSUPPORTED",
    "credential_isolation": "UNSUPPORTED",
    "hard_memory_quota": "UNSUPPORTED",
}

_ALLOWED_OPERATION_PREFIX = "test."
_DISALLOWED_REVERSIBILITY = {"IRREVERSIBLE", "UNKNOWN"}

Executor = Callable[[eb.ExecutionRequest], Awaitable[ExecutionOutcome | tuple[str, bytes, bytes]]]
"""Async executor returning ``(status, usage_jcs, result_error_jcs)``."""


async def _default_executor(request: eb.ExecutionRequest) -> tuple[str, bytes, bytes]:
    """Trivial effect-free workload: succeed with a deterministic artifact."""

    return "SUCCEEDED", canonical_json({}), b""


class _RequestRecord:
    """One submitted request in the fake durable state."""

    __slots__ = (
        "request",
        "state",
        "handle_bytes",
        "incarnation",
        "result",
        "effect_state_unknown",
        "terminal_acknowledged",
        "retained_until_us",
        "created_at_us",
        "updated_at_us",
    )

    def __init__(self, request: eb.ExecutionRequest, now_us: int) -> None:
        self.request = eb.ExecutionRequest()
        self.request.CopyFrom(request)
        self.request.authority_token = b""  # never retained (§41.41)
        self.state = "PREPARED"
        self.handle_bytes = uuid.uuid4().bytes
        self.incarnation = 1
        self.result: eb.ExecutionResult | None = None
        self.effect_state_unknown = False
        self.terminal_acknowledged = False
        self.retained_until_us = now_us + max(request.requested_retention_us, 0)
        self.created_at_us = now_us
        self.updated_at_us = now_us


class DurableFakeBackendState:
    """Injectable durable state for InMemory contract tests.

    ``to_bytes``/``restore_bytes`` simulate restart: a backend rebuilt on the
    restored state must behave identically for idempotent submit, terminal
    commits, and acknowledgements.
    """

    def __init__(self) -> None:
        self._requests: dict[tuple[str, str], _RequestRecord] = {}
        self._by_handle: dict[bytes, tuple[str, str]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._effect_log: list[dict[str, Any]] = []
        self._clock: Callable[[], int] = lambda: time.time_ns() // 1000

    # -- time injection ------------------------------------------------------
    def set_clock(self, now_us: Callable[[], int]) -> None:
        self._clock = now_us

    def now_us(self) -> int:
        return int(self._clock())

    # -- observation helpers for tests ---------------------------------------
    @property
    def effect_log(self) -> list[dict[str, Any]]:
        """Executed workload entries; contract tests assert at most one entry
        per non-idempotent request across crash/cancel/duplicate delivery."""
        return self._effect_log

    def record_effect(self, entry: dict[str, Any]) -> None:
        self._effect_log.append(entry)

    # -- restart surface ------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Serialize to wire-shaped records (protobuf objects reference
        generated module paths pickle cannot import, so we store bytes)."""

        return pickle.dumps(
            {
                "records": {k: self._dump_record(v) for k, v in self._requests.items()},
                "sessions": self._sessions,
                "effect_log": self._effect_log,
            }
        )

    @staticmethod
    def _dump_record(record: _RequestRecord) -> dict[str, Any]:
        return {
            "request": record.request.SerializeToString(),
            "state": record.state,
            "handle_bytes": record.handle_bytes,
            "incarnation": record.incarnation,
            "result": record.result.SerializeToString() if record.result else None,
            "effect_state_unknown": record.effect_state_unknown,
            "terminal_acknowledged": record.terminal_acknowledged,
            "retained_until_us": record.retained_until_us,
            "created_at_us": record.created_at_us,
            "updated_at_us": record.updated_at_us,
        }

    @classmethod
    def _load_record(cls, data: dict[str, Any]) -> _RequestRecord:
        request = eb.ExecutionRequest()
        request.ParseFromString(data["request"])
        record = _RequestRecord.__new__(_RequestRecord)
        record.request = request
        record.state = data["state"]
        record.handle_bytes = data["handle_bytes"]
        record.incarnation = data["incarnation"]
        if data["result"] is not None:
            record.result = eb.ExecutionResult()
            record.result.ParseFromString(data["result"])
        else:
            record.result = None
        record.effect_state_unknown = data["effect_state_unknown"]
        record.terminal_acknowledged = data["terminal_acknowledged"]
        record.retained_until_us = data["retained_until_us"]
        record.created_at_us = data["created_at_us"]
        record.updated_at_us = data["updated_at_us"]
        return record

    def restore_bytes(self, raw: bytes) -> None:
        data = pickle.loads(raw)
        self._requests = {key: self._load_record(d) for key, d in data["records"].items()}
        self._by_handle = {r.handle_bytes: key for key, r in self._requests.items()}
        self._sessions = data["sessions"]
        self._effect_log = data["effect_log"]


def _handle_for(
    backend_id: str, session_id: str, record: _RequestRecord
) -> eb.ExecutionHandle:
    return eb.ExecutionHandle(
        backend_id=backend_id,
        session_id=session_id,
        opaque_handle=record.handle_bytes,
        incarnation=record.incarnation,
        expires_at_us=0,
        request_id=record.request.request_id,
    )


def _snapshot(
    record: _RequestRecord, backend_id: str, session_id: str, now_us: int
) -> eb.ExecutionSnapshot:
    # A terminal result is reported as TERMINAL (ledger-state vocabulary),
    # with the concrete outcome carried in ``terminal.status``.
    snap = eb.ExecutionSnapshot(
        handle=_handle_for(backend_id, session_id, record),
        status="TERMINAL" if record.result is not None else record.state,
        observed_at_us=now_us,
    )
    if record.result is not None:
        snap.terminal.CopyFrom(record.result)
    return snap


class InMemoryBackend:
    """Contract-faithful in-memory backend for tests and local development."""

    def __init__(
        self,
        state: DurableFakeBackendState | None = None,
        *,
        backend_id: str = "backend://inmemory",
        executor: Executor | None = None,
        authorize: Callable[[eb.ExecutionRequest], Any] | None = None,
        maximum_requests: int = 4096,
        maximum_retained_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._state = state or DurableFakeBackendState()
        self._backend_id = backend_id
        self._executor: Executor = executor or _default_executor  # type: ignore[assignment]
        self._tasks: dict[tuple[str, str], asyncio.Task[None]] = {}
        self._open_sessions: set[str] = set()
        self._closed_sessions: set[str] = set()
        self._authorize = authorize
        if type(maximum_requests) is not int or maximum_requests <= 0 or type(maximum_retained_bytes) is not int or maximum_retained_bytes <= 0:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Backend retention limits must be positive integers")
        self._maximum_requests = maximum_requests
        self._maximum_retained_bytes = maximum_retained_bytes

    # -- capabilities / session ----------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        return {
            "backend_id": self._backend_id,
            "profile": "PORTABLE",
            "features": dict(INMEMORY_FEATURES),
            "authorization": "INJECTED_VERIFIER" if self._authorize else "UNAUTHORIZED_CONTRACT_TEST_ONLY",
        }

    @property
    def state(self) -> DurableFakeBackendState:
        return self._state

    async def negotiate(self, hello: eb.ClientHello) -> eb.BackendSession:
        major, minor = negotiate_version(hello.supported, server_major=1, server_minor=0)
        available = dict(INMEMORY_FEATURES)
        select_features(hello.required_features, hello.optional_features, available)
        now = self._state.now_us()
        session = eb.BackendSession(
            protocol_major=major,
            protocol_minor=minor,
            backend_id=self._backend_id,
            session_id=uuid.uuid4().hex,
            profile="PORTABLE",
            features_jcs=canonical_json(available),
            limits_jcs=canonical_json({}),
            established_at_us=now,
        )
        self._state._sessions[session.session_id] = {"closed": False, "at_us": now}
        self._open_sessions.add(session.session_id)
        return session

    def _require_session(self, session_id, *, allow_closed=False):
        if not session_id or session_id not in self._open_sessions and not (allow_closed and session_id in self._closed_sessions):
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="no negotiated Backend session")

    def _reserve_capacity(self, request):
        now = self._state.now_us()
        for key, record in tuple(self._state._requests.items()):
            if record.terminal_acknowledged and record.retained_until_us <= now and key not in self._tasks:
                del self._state._requests[key]
                self._state._by_handle.pop(record.handle_bytes, None)
        # Reserve room for the bounded terminal metadata too; this is a logical
        # ledger limit, not a claimed OS hard-memory quota.
        reserved = sum(row.request.ByteSize() + 66 * 1024 for row in self._state._requests.values())
        if len(self._state._requests) >= self._maximum_requests or reserved + request.ByteSize() + 66 * 1024 > self._maximum_retained_bytes:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Backend unexpired request retention is full")

    # -- submit ----------------------------------------------------------------
    def _validate_request(self, request: eb.ExecutionRequest) -> None:
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
        if not request.realm_id or not request.dedupe_scope or request.requested_retention_us < 0 or request.deadline_at_us < 0:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Backend scope/retention/deadline is invalid")
        if request.ByteSize() > 16 * 1024 * 1024:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Backend request exceeds its byte ceiling")
        if request.deadline_at_us and self._state.now_us() >= request.deadline_at_us:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Backend request deadline has expired")
        if not request.operation_kind.startswith(_ALLOWED_OPERATION_PREFIX):
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message="InMemory backend only executes effect-free test workloads",
                details={"operation_kind": request.operation_kind},
            )
        if request.reversibility in _DISALLOWED_REVERSIBILITY:
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message="irreversible effects require a Managed backend",
                details={"reversibility": request.reversibility},
            )

    async def submit(self, request: eb.ExecutionRequest) -> eb.ExecutionHandle:
        self._validate_request(request)
        session_id = request.session_id
        self._require_session(session_id)
        if self._authorize is not None:
            self._authorize(request)
        key = (request.dedupe_scope, request.request_id)
        state = self._state
        existing = state._requests.get(key)
        if existing is not None:
            fields = ("realm_id", "operation_kind", "payload_hash", "idempotency_class", "reversibility", "deadline_at_us", "requested_retention_us")
            if any(getattr(existing.request, name) != getattr(request, name) for name in fields):
                raise StableError(
                    code=ErrorCode.IDEMPOTENCY_CONFLICT,
                    message="same request id submitted with different execution semantics",
                    details={"request_id": request.request_id},
                )
            if (
                existing.state in ("PREPARED", "RUNNING")
                and existing.result is None
                and key not in self._tasks
            ):
                # Response-lost-after-create / restart recovery: the record
                # has no live workload, so the replayed Submit re-spawns it.
                self._spawn(existing, session_id)
            return _handle_for(self._backend_id, session_id, existing)

        if any(rid == request.request_id for _, rid in state._requests):
            # Frozen Ack addresses request_id alone. A second scoped owner
            # would be ambiguous, so do not create one or execute its callback.
            raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Backend request identity is already owned by another scope")
        self._reserve_capacity(request)
        record = _RequestRecord(request, state.now_us())
        state._requests[key] = record
        state._by_handle[record.handle_bytes] = key
        self._spawn(record, session_id)
        return _handle_for(self._backend_id, session_id, record)

    def _spawn(self, record: _RequestRecord, session_id: str) -> None:
        """Start the fake workload for a fresh record (§41.48.2 flow)."""

        record.state = "RUNNING"
        record.updated_at_us = self._state.now_us()
        key = (record.request.dedupe_scope, record.request.request_id)
        incarnation = record.incarnation
        token = AuthorityToken(b"")  # token dropped at record time; never used

        async def run() -> None:
            try:
                value = await self._executor(record.request)
                outcome = value if isinstance(value, ExecutionOutcome) else ExecutionOutcome(*value)
            except Exception as exc:  # noqa: BLE001 - terminal must be reached
                failure = (
                    exc if isinstance(exc, StableError)
                    else StableError(code=ErrorCode.INTERNAL, message="executor failed")
                )
                outcome = ExecutionOutcome(
                    "FAILED",
                    canonical_json({}),
                    failure.canonical_bytes(),
                )
            self.commit_terminal(
                record.request.request_id,
                record.request.dedupe_scope,
                status=outcome.status,
                usage_jcs=outcome.usage_jcs,
                error_jcs=outcome.error_jcs,
                result_artifact_id=outcome.result_artifact_id,
                incarnation=incarnation,
            )

        task = asyncio.get_running_loop().create_task(run())
        self._tasks[key] = task
        def completed(worker):
            if self._tasks.get(key) is worker:
                self._tasks.pop(key, None)
            if not worker.cancelled():
                # Late/stale owners can be refused at terminal commit. Consume
                # that task exception; it must never become a second result.
                worker.exception()
        task.add_done_callback(completed)

    # -- terminal commit (owner-checked) ---------------------------------------
    def commit_terminal(
        self,
        request_id: str,
        dedupe_scope: str,
        *,
        status: str,
        usage_jcs: bytes = b"",
        error_jcs: bytes = b"",
        result_artifact_id: str = "",
        incarnation: int,
        authority_token: AuthorityToken | None = None,
        effect_state_unknown: bool = False,
    ) -> eb.ExecutionResult:
        """Terminal commit gated on the current incarnation.

        A stale owner (its incarnation predates a restart/renewal) must never
        commit a terminal result — refused with ``REVISION_CONFLICT``.
        """

        key = (dedupe_scope, request_id)
        record = self._state._requests.get(key)
        if record is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message=f"unknown request {request_id}"
            )
        if status not in TERMINAL_STATUSES:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message=f"non-terminal status {status}"
            )
        if incarnation != record.incarnation:
            raise StableError(
                code=ErrorCode.REVISION_CONFLICT,
                message="stale incarnation cannot commit terminal result",
                details={"incarnation": incarnation, "current": record.incarnation},
            )
        try:
            ExecutionOutcome(status, usage_jcs, error_jcs, result_artifact_id)
        except (ValueError, TypeError) as exc:
            raise StableError(code=ErrorCode.INVALID_RESULT, message="Backend terminal outcome is invalid") from exc
        if record.result is not None:
            old = record.result
            if (old.status, bytes(old.usage_jcs), bytes(old.error_jcs), old.result_artifact_id, old.effect_state_unknown) != (status, usage_jcs, error_jcs, result_artifact_id, effect_state_unknown):
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Backend terminal outcome conflicts with its first result")
            return record.result  # idempotent terminal replay
        if record.state == "UNKNOWN":
            raise StableError(
                code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                message="effect state unknown; terminal result refused",
            )
        result = eb.ExecutionResult(
            status=status,
            request_id=request_id,
            usage_jcs=usage_jcs,
            result_hash=payload_hash(error_jcs or result_artifact_id.encode("utf-8")),
            completed_at_us=self._state.now_us(),
            effect_state_unknown=effect_state_unknown,
        )
        if result_artifact_id:
            result.result_artifact_id = result_artifact_id
        if error_jcs:
            result.error_jcs = error_jcs
        record.result = result
        record.state = "UNKNOWN" if effect_state_unknown else status
        record.effect_state_unknown = effect_state_unknown
        record.updated_at_us = self._state.now_us()
        return result

    def renew_incarnation(self, request_id: str, dedupe_scope: str) -> int:
        """Recovery path: bump the incarnation so old owners are invalidated."""

        record = self._state._requests[(dedupe_scope, request_id)]
        record.incarnation += 1
        record.updated_at_us = self._state.now_us()
        return record.incarnation

    # -- await / inspect --------------------------------------------------------
    async def await_activity(
        self, handle: eb.ExecutionHandle, deadline_at_us: int
    ) -> eb.ExecutionResult:
        record = self._require_record(handle)
        while record.result is None and record.state != "UNKNOWN":
            now = self._state.now_us()
            if deadline_at_us and now >= deadline_at_us:
                raise StableError(
                    code=ErrorCode.DEADLINE_EXCEEDED,
                    message="not terminal before deadline",
                    details={"status": record.state},
                )
            await asyncio.sleep(0.005)
        if record.result is not None:
            return record.result
        raise StableError(
            code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
            message="workload state unknown",
        )

    def _require_record(self, handle: eb.ExecutionHandle) -> _RequestRecord:
        self._require_session(handle.session_id, allow_closed=True)
        if handle.backend_id != self._backend_id:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Backend handle identity mismatch")
        key = self._state._by_handle.get(bytes(handle.opaque_handle))
        if key is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown handle")
        record = self._state._requests[key]
        if handle.request_id != record.request.request_id:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Backend handle request mismatch")
        if handle.incarnation != record.incarnation:
            raise StableError(
                code=ErrorCode.HANDLE_EXPIRED, message="stale handle incarnation"
            )
        return record

    async def inspect(self, handle: eb.ExecutionHandle) -> eb.ExecutionSnapshot:
        record = self._require_record(handle)
        return _snapshot(record, self._backend_id, handle.session_id, self._state.now_us())

    # -- cancel ------------------------------------------------------------------
    async def cancel(self, request: eb.CancelRequest) -> eb.CancelReport:
        record = self._require_record(request.handle)
        mode = request.mode or "GRACEFUL"
        if mode not in ("GRACEFUL", "FORCE") or request.deadline_at_us < 0:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Backend cancellation mode/deadline is invalid")
        if record.state == "UNKNOWN":
            return eb.CancelReport(status="UNKNOWN", terminal_confirmed=False, details_jcs=canonical_json({}))
        if record.result is not None:
            return eb.CancelReport(
                status=record.state,
                terminal_confirmed=True,
                details_jcs=canonical_json({}),
            )
        key = (record.request.dedupe_scope, record.request.request_id)
        task = self._tasks.get(key)
        if task is not None and not task.done():
            task.cancel()
            deadline = request.deadline_at_us or self._state.now_us() + 5_000_000
            remaining = max(0, min(5_000_000, deadline - self._state.now_us())) / 1_000_000
            done, _ = await asyncio.wait({task}, timeout=remaining)
            if not done:
                record.state, record.effect_state_unknown = "UNKNOWN", True
                record.updated_at_us = self._state.now_us()
                return eb.CancelReport(status="UNKNOWN", terminal_confirmed=False, details_jcs=canonical_json({}))
        if mode == "FORCE" and record.result is None:
            # Forced cancellation with no observed terminal: effect state is
            # unknown and the workload can never commit a result afterwards.
            record.state = "UNKNOWN"
            record.effect_state_unknown = True
            record.updated_at_us = self._state.now_us()
            return eb.CancelReport(
                status="UNKNOWN", terminal_confirmed=False, details_jcs=canonical_json({})
            )
        if record.result is not None:
            return eb.CancelReport(
                status=record.state,
                terminal_confirmed=True,
                details_jcs=canonical_json({}),
            )
        result = eb.ExecutionResult(
            status="CANCELLED",
            request_id=record.request.request_id,
            result_hash=payload_hash(b"cancelled"),
            completed_at_us=self._state.now_us(),
        )
        record.result = result
        record.state = "CANCELLED"
        record.updated_at_us = self._state.now_us()
        return eb.CancelReport(
            status="CANCELLED", terminal_confirmed=True, details_jcs=canonical_json({})
        )

    # -- reconcile / ack / close ---------------------------------------------------
    async def reconcile(self, request: eb.ReconcileRequest) -> eb.ReconcileReport:
        self._require_session(request.session_id)
        now = self._state.now_us()
        report = eb.ReconcileReport(observed_at_us=now)
        seen = set()
        for known in request.known:
            matches = [(key, r) for key, r in self._state._requests.items()
                if key[1] == known.request_id and r.request.realm_id == request.realm_id
                and (not known.payload_hash or known.payload_hash == r.request.payload_hash)
                and (not known.handle.opaque_handle or bytes(known.handle.opaque_handle) == r.handle_bytes)]
            if not matches:
                continue
            if len(matches) != 1:
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Backend binding identity is ambiguous")
            key, record = matches[0]
            seen.add(key)
            binding = report.bindings.add()
            binding.known.CopyFrom(known)
            binding.status = "TERMINAL" if record.result is not None else record.state
            if record.result is not None:
                binding.terminal.CopyFrom(record.result)
            else:
                binding.renewed_handle.CopyFrom(
                    _handle_for(self._backend_id, request.session_id, record)
                )
        for (scope, request_id), record in self._state._requests.items():
            if (scope, request_id) in seen or record.request.realm_id != request.realm_id:
                continue
            if record.state in ("RUNNING", "PREPARED", "UNKNOWN"):
                orphan = report.orphans.add()
                orphan.handle.CopyFrom(
                    _handle_for(self._backend_id, request.session_id, record)
                )
                orphan.request_id = request_id
                orphan.payload_hash = record.request.payload_hash
                orphan.recommended_action = "INSPECT_THEN_DECIDE"
        return report

    async def acknowledge_terminal(self, request: eb.TerminalAck) -> eb.AckReport:
        self._require_session(request.session_id, allow_closed=True)
        matches = [record for record in self._state._requests.values() if record.request.request_id == request.request_id]
        if len(matches) > 1:
            raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Backend acknowledgement identity is ambiguous")
        for record in matches:
            if record.result is None:
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="request not terminal"
                )
            if request.result_hash != record.result.result_hash:
                raise StableError(
                    code=ErrorCode.REVISION_CONFLICT,
                    message="acknowledgement hash mismatch",
                )
            if not record.terminal_acknowledged:
                record.terminal_acknowledged = True
                record.retained_until_us = max(record.retained_until_us, self._state.now_us() + 3_600_000_000)
            return eb.AckReport(
                status="ACKNOWLEDGED", retained_until_us=record.retained_until_us
            )
        raise StableError(
            code=ErrorCode.NOT_FOUND, message=f"unknown request {request.request_id}"
        )

    async def close_session(self, session: eb.BackendSession) -> eb.CloseReport:
        self._require_session(session.session_id, allow_closed=True)
        if session.backend_id != self._backend_id:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Backend session identity mismatch")
        self._open_sessions.discard(session.session_id)
        self._closed_sessions.add(session.session_id)
        now = self._state.now_us()
        self._state._sessions[session.session_id] = {"closed": True, "at_us": now}
        return eb.CloseReport(
            status="CLOSED", session_id=session.session_id, closed_at_us=now
        )
