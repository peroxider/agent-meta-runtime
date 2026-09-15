"""Portable Backend adapter (§41.48, §41.27).

Composes the durable request ledger, worker directories, and the platform
cancellation ladder into the frozen eight-RPC backend session contract. The
submit flow follows §41.48.2 exactly: PREPARED insert under BEGIN IMMEDIATE,
request directory + request.jcs, worker spawn with a 128-bit launch nonce,
claim/started observation, TERMINAL recording when result.jcs appears. The
feature profile is honest: isolation/quota features report PARTIAL or
UNSUPPORTED, and workloads requiring them are rejected with
``FEATURE_UNAVAILABLE`` (§41.48.4).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...protocols._v1 import execution_backend_pb2 as eb
from ...protocols.backend_wire import negotiate_version, payload_hash, select_features
from . import cancellation, environment, worker, worker_entry
from .ledger import PortableRequestLedger

__all__ = ["PORTABLE_FEATURES", "PortableBackend"]

#: Honest default Portable feature profile (§41.48.4): containment for
#: trusted code only — never claimed as SUPPORTED for isolation features.
PORTABLE_FEATURES: dict[str, str] = {
    "process": "SUPPORTED",
    "activity": "SUPPORTED",
    "channel": "SUPPORTED",
    "workspace": "SUPPORTED",
    "persistent_idempotency": "SUPPORTED",
    "isolated_realm": "UNSUPPORTED",
    "network_isolation": "UNSUPPORTED",
    "credential_isolation": "UNSUPPORTED",
    "hard_memory_quota": "PARTIAL",
}


class PortableBackend:
    """Local Portable backend: ledger + spawned isolated-mode workers."""

    def __init__(
        self,
        data_dir: Path,
        *,
        backend_id: str = "backend://portable",
        profile: str = "PORTABLE",
        clock: Any = None,
        poll_interval_s: float = 0.02,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._backend_id = backend_id
        self._profile = profile
        (self._data_dir / "backend").mkdir(parents=True, exist_ok=True)
        self._ledger = PortableRequestLedger(
            str(self._data_dir / "backend" / "portable.db"), backend_id=backend_id
        )
        self._clock = clock or (lambda: time.time_ns() // 1000)
        self._poll_interval_s = poll_interval_s
        self._closed_sessions: set[str] = set()
        self._children: dict[str, subprocess.Popen] = {}

    # -- capabilities / session -------------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        return {
            "backend_id": self._backend_id,
            "profile": self._profile,
            "features": dict(PORTABLE_FEATURES),
        }

    async def negotiate(self, hello: eb.ClientHello) -> eb.BackendSession:
        major, minor = negotiate_version(hello.supported, server_major=1, server_minor=0)
        # Required features that Portable cannot honestly support fail here.
        select_features(hello.required_features, hello.optional_features, PORTABLE_FEATURES)
        session = eb.BackendSession(
            protocol_major=major,
            protocol_minor=minor,
            backend_id=self._backend_id,
            session_id=uuid.uuid4().hex,
            profile=self._profile,
            features_jcs=canonical_json(PORTABLE_FEATURES),
            limits_jcs=canonical_json(
                {
                    "task_workspace_bytes": environment.TASK_QUOTA_BYTES,
                    "scratch_workspace_bytes": environment.SCRATCH_QUOTA_BYTES,
                    "stdout_bytes": 8 * 1024 * 1024,
                    "stderr_bytes": 8 * 1024 * 1024,
                }
            ),
            established_at_us=self._clock(),
        )
        return session

    # -- submit -------------------------------------------------------------------
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
        if request.operation_kind not in worker_entry.BUILTIN_HANDLERS:
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message=f"operation_kind not registered: {request.operation_kind}",
            )
        if request.reversibility in ("IRREVERSIBLE", "UNKNOWN"):
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message="Portable v0.1 rejects high-risk irreversible effects",
                details={"reversibility": request.reversibility},
            )

    def _spawn_worker(self, request_dir: Path, expected_hash: str, nonce: bytes) -> subprocess.Popen:
        python = sys.executable
        env = environment.build_worker_env(
            runtime_paths=[str(Path(python).parent)],
            request_id=request_dir.name,
            workspace_relpath=str(request_dir.relative_to(self._data_dir)),
        )
        env["AGENT_META_LAUNCH_NONCE"] = nonce.hex()
        argv = [python, "-m", worker_entry.__name__, str(request_dir), expected_hash]
        kwargs: dict[str, Any] = {
            "cwd": str(request_dir),
            "env": env,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            kwargs["creationflags"] = subprocess.CREATE_SUSPENDED
            proc = subprocess.Popen(argv, **kwargs)
            _assign_job_object(proc.pid)
            import ctypes

            ctypes.windll.kernel32.ResumeThread(  # type: ignore[attr-defined]
                proc._handle  # type: ignore[attr-defined]
            )
        else:
            proc = subprocess.Popen(argv, start_new_session=True, **kwargs)
        return proc

    async def submit(self, request: eb.ExecutionRequest) -> eb.ExecutionHandle:
        self._validate_request(request)
        if not request.session_id or request.session_id in self._closed_sessions:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="no open session"
            )
        request_id = request.request_id
        try:
            uuid.UUID(request_id)
        except ValueError as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="request id must be a UUID"
            ) from exc
        now = self._clock()
        relpath = f"workloads/{request_id}/request.jcs"
        record = self._ledger.submit(
            request_id=request_id,
            realm_id=request.realm_id,
            operation_kind=request.operation_kind,
            payload_hash=request.payload_hash,
            payload_jcs=bytes(request.payload_jcs),
            idempotency_class=request.idempotency_class or "NONE",
            reversibility=request.reversibility or "REVERSIBLE",
            request_relpath=relpath,
            now_us=now,
            requested_retention_us=request.requested_retention_us,
        )
        request_dir = worker.request_directory(self._data_dir, request_id)
        if record["created"]:
            await self._launch(request, request_dir)
        else:
            # Replay (§41.48.2): a PREPARED request with no claim and no
            # result may be re-spawned — covers crash between ledger commit
            # and worker spawn, and response-lost-after-create. If the
            # worker already produced a result, record it instead.
            self._observe_result(request_id, request_dir)
            record = self._ledger.get(request_id)
            assert record is not None
            if record["state"] == "PREPARED" and worker.read_claim(request_dir) is None:
                await self._launch(request, request_dir)
        return eb.ExecutionHandle(
            backend_id=self._backend_id,
            session_id=request.session_id,
            opaque_handle=record["handle_bytes"],
            incarnation=1,
            expires_at_us=0,
            request_id=request_id,
        )

    async def _launch(self, request: eb.ExecutionRequest, request_dir: Path) -> None:
        """Write the request file and spawn the worker for this request."""

        request_id = request.request_id
        nonce = worker.new_launch_nonce()
        payload = json.loads(bytes(request.payload_jcs).decode("utf-8"))
        payload["operation_kind"] = request.operation_kind
        payload_bytes = canonical_json(payload)
        worker.write_request_file(request_dir, payload_bytes)
        (request_dir / "launch_nonce").write_bytes(nonce)
        proc = self._spawn_worker(request_dir, payload_hash(payload_bytes), nonce)
        self._children[request_id] = proc
        await self._observe_claim(request_id, request_dir, nonce, proc.pid)

    async def _observe_claim(
        self, request_id: str, request_dir: Path, nonce: bytes, pid: int
    ) -> None:
        """Wait for the worker claim; record CLAIMED/RUNNING in the ledger."""

        expected_nonce_hash = worker.nonce_hash(nonce)
        deadline = asyncio.get_running_loop().time() + 10.0
        while True:
            claim = worker.read_claim(request_dir)
            if claim is not None and claim.get("nonce_hash") == expected_nonce_hash:
                self._ledger.mark_claimed(
                    request_id,
                    worker_pid=claim.get("pid", pid),
                    worker_start_identity=str(claim.get("start_identity", "")),
                    launch_nonce_hash=expected_nonce_hash,
                    now_us=self._clock(),
                )
                break
            if worker.read_result(request_dir) is not None:
                return  # fast-path: worker finished before claim was observed
            if asyncio.get_running_loop().time() > deadline:
                return  # recovery path classifies the abandoned claim later
            await asyncio.sleep(self._poll_interval_s)
        if (request_dir / worker.STARTED_FILE).exists():
            self._ledger.mark_running(request_id, now_us=self._clock())

    # -- await / inspect -------------------------------------------------------------
    def _record_to_snapshot(
        self, record: dict[str, Any], handle: eb.ExecutionHandle | None
    ) -> eb.ExecutionSnapshot:
        snap = eb.ExecutionSnapshot(
            handle=handle
            or eb.ExecutionHandle(
                backend_id=self._backend_id,
                session_id="",
                opaque_handle=record["handle_bytes"],
                incarnation=1,
                expires_at_us=0,
                request_id=record["request_id"],
            ),
            status=record["state"],
            observed_at_us=self._clock(),
        )
        if record["result_jcs"] is not None:
            result = eb.ExecutionResult(
                status="SUCCEEDED",
                request_id=record["request_id"],
                result_hash=record["result_hash"] or "",
                completed_at_us=record["completed_at_us"] or self._clock(),
                effect_state_unknown=bool(record["effect_state_unknown"]),
            )
            try:
                parsed = json.loads(bytes(record["result_jcs"]).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                parsed = {}
            result.status = parsed.get("status", record["state"])
            result.usage_jcs = parsed.get("usage_jcs", "{}").encode("utf-8")
            outcome = parsed.get("result_jcs", "{}")
            if result.status == "FAILED":
                result.error_jcs = outcome.encode("utf-8")
            snap.terminal.CopyFrom(result)
        return snap

    def _observe_result(self, request_id: str, request_dir: Path) -> None:
        """Parent/recovery side: result.jcs → TERMINAL in the ledger."""

        result = worker.read_result(request_dir)
        if result is None:
            return
        record = self._ledger.get(request_id)
        if record is None or record["state"] == "TERMINAL":
            return
        result_bytes = canonical_json(result)
        self._ledger.mark_terminal(
            request_id,
            result_hash=payload_hash(result_bytes),
            result_jcs=result_bytes,
            now_us=self._clock(),
        )

    def _require_record(self, handle: eb.ExecutionHandle) -> dict[str, Any]:
        record = self._ledger.get(handle.request_id)
        if record is None:
            raise StableError(code=ErrorCode.NOT_FOUND, message="unknown handle")
        return record

    async def await_activity(
        self, handle: eb.ExecutionHandle, deadline_at_us: int
    ) -> eb.ExecutionResult:
        record = self._require_record(handle)
        request_dir = worker.request_directory(self._data_dir, record["request_id"])
        while True:
            self._observe_result(record["request_id"], request_dir)
            current = self._ledger.get(record["request_id"])
            assert current is not None
            if current["state"] == "TERMINAL":
                return self._record_to_snapshot(current, handle).terminal
            if current["state"] == "UNKNOWN":
                raise StableError(
                    code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
                    message="workload effect state unknown",
                )
            now = self._clock()
            if deadline_at_us and now >= deadline_at_us:
                snapshot = self._record_to_snapshot(current, handle)
                raise StableError(
                    code=ErrorCode.DEADLINE_EXCEEDED,
                    message="not terminal before deadline",
                    details={
                        "status": current["state"],
                        "snapshot_status": snapshot.status,
                    },
                )
            await asyncio.sleep(self._poll_interval_s)

    async def inspect(self, handle: eb.ExecutionHandle) -> eb.ExecutionSnapshot:
        record = self._require_record(handle)
        request_dir = worker.request_directory(self._data_dir, record["request_id"])
        self._observe_result(record["request_id"], request_dir)
        current = self._ledger.get(record["request_id"])
        assert current is not None
        return self._record_to_snapshot(current, handle)

    # -- cancel ------------------------------------------------------------------------
    async def cancel(self, request: eb.CancelRequest) -> eb.CancelReport:
        record = self._require_record(request.handle)
        request_dir = worker.request_directory(self._data_dir, record["request_id"])
        self._observe_result(record["request_id"], request_dir)
        current = self._ledger.get(record["request_id"])
        assert current is not None
        if current["state"] == "TERMINAL":
            result_status = self._record_to_snapshot(current, request.handle).terminal.status
            return eb.CancelReport(
                status=result_status or current["state"],
                terminal_confirmed=True,
                details_jcs=canonical_json({}),
            )
        pid = current["worker_pid"]
        identity = current["worker_start_identity"]
        child = self._children.get(record["request_id"])
        if pid and identity:
            confirmed, details = cancellation.cancel_process_tree(
                request_dir,
                int(pid),
                str(identity),
                mode=request.mode or "GRACEFUL",
                reap=child.poll if child is not None else None,
            )
        else:
            # Never claimed: safe to classify as cancelled without a worker.
            confirmed, details = True, {"steps": ["no_claim"]}
        if child is not None:
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            self._children.pop(record["request_id"], None)
        self._observe_result(record["request_id"], request_dir)
        after = self._ledger.get(record["request_id"])
        assert after is not None
        if after["state"] == "TERMINAL":
            if not confirmed:
                raise StableError(
                    code=ErrorCode.INTERNAL,
                    message="terminal result without confirmed exit",
                )
            result_status = self._record_to_snapshot(after, request.handle).terminal.status
            return eb.CancelReport(
                status=result_status,
                terminal_confirmed=True,
                details_jcs=canonical_json(details),
            )
        if confirmed:
            # Worker tree exited but produced no result: cancel is terminal.
            result = canonical_json({"status": "CANCELLED"})
            self._ledger.mark_terminal(
                record["request_id"],
                result_hash=payload_hash(result),
                result_jcs=result,
                now_us=self._clock(),
            )
            return eb.CancelReport(
                status="CANCELLED",
                terminal_confirmed=True,
                details_jcs=canonical_json(details),
            )
        self._ledger.mark_unknown(
            record["request_id"], now_us=self._clock(), reason="cancel_unconfirmed"
        )
        return eb.CancelReport(
            status="UNKNOWN",
            terminal_confirmed=False,
            details_jcs=canonical_json(details),
        )

    # -- reconcile / ack / close ---------------------------------------------------------
    def _classify_recovery(self, record: dict[str, Any]) -> str:
        """Recovery classification per §41.48.2 (claim liveness)."""

        request_dir = worker.request_directory(self._data_dir, record["request_id"])
        self._observe_result(record["request_id"], request_dir)
        current = self._ledger.get(record["request_id"])
        assert current is not None
        if current["state"] in ("TERMINAL", "UNKNOWN"):
            return current["state"]
        claim = worker.read_claim(request_dir)
        if claim is None:
            return "PREPARED"  # spawnable: no claim, no started
        pid = claim.get("pid")
        identity = str(claim.get("start_identity", ""))
        child = self._children.get(record["request_id"])
        if child is not None:
            child.poll()  # reap exited children before the liveness check
        if pid and worker.process_start_identity(int(pid)) == identity:
            return "RUNNING"  # live claim owner
        # Dead owner, no terminal result → UNKNOWN fail-closed.
        return "UNKNOWN"

    async def reconcile(self, request: eb.ReconcileRequest) -> eb.ReconcileReport:
        report = eb.ReconcileReport(observed_at_us=self._clock())
        handled: set[str] = set()
        for known in request.known:
            handled.add(known.request_id)
            record = self._ledger.get(known.request_id)
            if record is None or record["realm_id"] != request.realm_id:
                continue
            status = self._classify_recovery(record)
            if status == "UNKNOWN" and record["state"] != "UNKNOWN":
                self._ledger.mark_unknown(
                    known.request_id,
                    now_us=self._clock(),
                    reason="dead_claim_owner",
                )
            binding = report.bindings.add()
            binding.known.CopyFrom(known)
            binding.status = status
            if status in ("TERMINAL", "UNKNOWN"):
                binding.terminal.CopyFrom(
                    self._record_to_snapshot(record, known.handle).terminal
                )
            else:
                binding.renewed_handle.CopyFrom(known.handle)
        for candidate in self._ledger.recovery_candidates():
            if (
                candidate["request_id"] in handled
                or candidate["realm_id"] != request.realm_id
            ):
                continue
            if candidate["state"] in ("PREPARED", "CLAIMED", "RUNNING"):
                self._classify_recovery(candidate)
                orphan = report.orphans.add()
                orphan.request_id = candidate["request_id"]
                orphan.payload_hash = candidate["payload_hash"]
                status = candidate["state"]
                orphan.recommended_action = (
                    "RESUBMIT_TO_RECOVER" if status == "PREPARED" else "INSPECT_THEN_DECIDE"
                )
        return report

    async def acknowledge_terminal(self, request: eb.TerminalAck) -> eb.AckReport:
        record = self._ledger.get(request.request_id)
        if record is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message=f"unknown request {request.request_id}",
            )
        retained = self._ledger.acknowledge_terminal(
            request.request_id,
            result_hash=request.result_hash,
            retained_until_us=self._clock() + 3_600_000_000,
            now_us=self._clock(),
        )
        return eb.AckReport(status="ACKNOWLEDGED", retained_until_us=retained)

    async def close_session(self, session: eb.BackendSession) -> eb.CloseReport:
        self._closed_sessions.add(session.session_id)
        return eb.CloseReport(
            status="CLOSED", session_id=session.session_id, closed_at_us=self._clock()
        )


def _assign_job_object(pid: int) -> None:  # pragma: no cover - Windows only
    """Assign a (suspended) child to a kill-on-close Job Object (§41.48.3)."""

    import ctypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    job = kernel32.CreateJobObjectW(None, None)
    info = ctypes.create_string_buffer(144)
    # JOBOBJECT_EXTENDED_LIMIT_INFORMATION: LimitFlags (0x2000 =
    # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) sits at offset 64 bytes.
    struct_ptr = ctypes.cast(info, ctypes.POINTER(ctypes.c_uint64))
    struct_ptr[8] = 0x2000
    kernel32.SetInformationJobObject(job, 9, info, ctypes.sizeof(info))
    handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
    kernel32.AssignProcessToJobObject(job, handle)
    kernel32.CloseHandle(handle)
