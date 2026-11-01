"""Bounded controller for the fixed Runtime Provider enforcement worker.

Caller MUST durably admit the Invocation/attempt and reserve its budget before
calling run(), then commit the returned outcome. This cache is session-only.
No request bytes leave the parent before actual native ownership is observed.
"""
import asyncio
from dataclasses import dataclass, field, replace
import os
import subprocess
import sys
import threading
import time
import uuid

from ..domain.canonical import now_us
from ..domain.errors import ErrorCode, StableError
from ..domain.provider_transport import ProviderHttpOutcome, ProviderHttpRequest, authorize_provider_request
from ..domain.execution_tokens import ExecutionTokenBinding
from ..ports.provider_transport import ProviderWorkerInterrupted
from .owned_worker import OwnedWindowsJob, WorkerProcessLifetime
from .provider_worker_wire import (ProviderWorkerBootstrap, command, document, parse_outcome,
    read_frame, write_frame)


def _failure(sent, reason):
    return ProviderHttpOutcome("UNKNOWN" if sent else "NOT_SENT",
        error_code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN if sent else ErrorCode.BACKEND_UNAVAILABLE,
        reason_code=reason)


@dataclass
class _Entry:
    fingerprint: str
    done: asyncio.Event = field(default_factory=asyncio.Event)
    outcome: ProviderHttpOutcome | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    launcher_pid: int | None = None
    worker_pid: int | None = None
    request_started: bool = False
    exit_confirmed: bool = False
    lifetime: object | None = None


class ProviderWorkerController:
    def __init__(self, bootstrap: ProviderWorkerBootstrap, *, maximum_processes=4, maximum_requests=128):
        if not isinstance(bootstrap, ProviderWorkerBootstrap) or type(maximum_processes) is not int or not 1 <= maximum_processes <= 16 or type(maximum_requests) is not int or not 1 <= maximum_requests <= 1024:
            raise ValueError("invalid Provider worker configuration")
        # A controller restart is a new native session, never restoration of
        # the previous process/cache. Old signed requests cannot cross it.
        self._bootstrap = replace(bootstrap, session_id="provider-worker/" + uuid.uuid4().hex)
        self._verifier = bootstrap.verifier()
        self._slots = asyncio.Semaphore(maximum_processes)
        self._maximum = maximum_requests
        self._entries = {}
        self._owners = set()
        self._closed = False
        self._broken = False

    @property
    def session_id(self):
        return self._bootstrap.session_id

    def observation(self, request_id):
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        with entry.lock:
            return {"launcher_pid": entry.launcher_pid, "worker_pid": entry.worker_pid,
                "request_started": entry.request_started, "exit_confirmed": entry.exit_confirmed,
                "terminal": entry.done.is_set()}

    async def run(self, request, *, authorization, binding):
        if self._closed or self._broken:
            raise StableError(code=ErrorCode.BACKEND_UNAVAILABLE, message="Provider worker session is closed")
        if not isinstance(request, ProviderHttpRequest) or not isinstance(binding, ExecutionTokenBinding):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid Provider worker request")
        if request.deadline_at_us is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Provider worker requires an absolute deadline")
        boot = self._bootstrap
        if (binding.backend_session_id, binding.realm_id, binding.epoch_id) != (boot.session_id, boot.realm_id, boot.epoch_id):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider worker session differs")
        _audit, remaining, fingerprint = authorize_provider_request(self._verifier, request,
            authorization=authorization, binding=binding, now_us=now_us())
        if remaining <= 0:
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="Provider worker deadline expired")
        if request.policy.profile == "PUBLIC_HTTPS" and boot.credential_profile != "WINDOWS_DPAPI_CURRENT_USER":
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="public Provider worker requires protected credentials")
        entry = self._entries.get(request.request_id)
        if entry is not None:
            if entry.fingerprint != fingerprint:
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="Provider worker request identity changed")
            # A cancelled observer does not restart or cancel the owner.
            try:
                await asyncio.wait_for(entry.done.wait(), remaining / 1_000_000)
            except TimeoutError:
                return _failure(True, "WORKER_IN_FLIGHT")
            return entry.outcome
        if len(self._entries) >= self._maximum:
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Provider worker session retention is full")
        entry = self._entries[request.request_id] = _Entry(fingerprint)
        owner = asyncio.current_task()
        self._owners.add(owner)
        outcome = _failure(False, "WORKER_NOT_STARTED")
        interrupted = False
        timed_out = False
        finish_deadline = time.monotonic() + remaining / 1_000_000
        process = job = exchange = None
        acquired = False
        try:
            async with asyncio.timeout(remaining / 1_000_000):
                await self._slots.acquire()
                acquired = True
                await asyncio.sleep(0)
                if os.name == "nt":
                    job = OwnedWindowsJob()
                elif not sys.platform.startswith("linux"):
                    raise OSError("Provider worker ownership unavailable")
                args = [sys.executable, "-I", "-u", "-m", "agent_meta_runtime.adapters.provider_worker_process",
                    "--parent-pid", str(os.getpid())]
                if job is not None:
                    args += ["--job-name", job.name]
                environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP") if key in os.environ}
                # No await during process creation: cancellation cannot discard
                # an unobserved child. At most maximum_processes launches can
                # occupy the event-loop turn before yielding to their I/O.
                process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, env=environment, cwd=boot.credential_root, close_fds=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                with entry.lock:
                    entry.launcher_pid = process.pid
                payload = command(boot, request, authorization=authorization, binding=binding)
                exchange = asyncio.create_task(asyncio.to_thread(self._exchange, process, job, entry, payload))
                outcome = await asyncio.shield(exchange)
        except asyncio.CancelledError:
            interrupted = True
            with entry.lock:
                outcome = _failure(entry.request_started, "WORKER_CANCELLED")
        except TimeoutError:
            timed_out = True
            with entry.lock:
                outcome = _failure(entry.request_started, "WORKER_TIMEOUT")
        except Exception:
            with entry.lock:
                outcome = _failure(entry.request_started, "WORKER_FAILURE")
        finally:
            entry.stop.set()
            cleanup = asyncio.create_task(self._reap(process, job, exchange, entry))
            # Repeated cancellation must not abandon native cleanup. The final
            # interruption still reaches the caller with a journalable outcome.
            while True:
                try:
                    await asyncio.shield(cleanup)
                    break
                except asyncio.CancelledError:
                    interrupted = True
                except Exception:
                    self._broken = True
                    with entry.lock:
                        outcome = _failure(entry.request_started, "WORKER_CLEANUP_UNCONFIRMED")
                    break
            if acquired and not self._broken:
                self._slots.release()
            if exchange is not None and exchange.done() and not exchange.cancelled() and not self._broken and not timed_out:
                try:
                    # Preserve a complete native result even if cancellation
                    # raced its delivery; the caller still receives interruption
                    # and may not dispatch another effect for a cancelled Task.
                    outcome = exchange.result()
                except Exception:
                    pass
            if not interrupted and outcome.content is not None and (
                    time.monotonic() >= finish_deadline or now_us() >= request.deadline_at_us):
                outcome = _failure(True, "WORKER_TIMEOUT")
            self._owners.discard(owner)
            with entry.lock:
                entry.outcome = outcome
                entry.done.set()
        if interrupted:
            raise ProviderWorkerInterrupted(outcome)
        return outcome

    @staticmethod
    def _exchange(process, job, entry, payload):
        ready = document(read_frame(process.stdout))
        if set(ready) != {"schema", "status", "pid"} or ready["schema"] != "provider-worker-ready/v1" or ready["status"] != "READY" or type(ready["pid"]) is not int or ready["pid"] <= 0:
            raise ValueError("Provider worker did not establish ownership")
        with entry.lock:
            entry.worker_pid = ready["pid"]
        if job is not None:
            if not job.contains(ready["pid"]):
                raise ValueError("actual Provider worker is outside its owner Job")
        elif ready["pid"] != process.pid:
            raise ValueError("Provider worker PID differs")
        lifetime = WorkerProcessLifetime(ready["pid"])
        with entry.lock:
            entry.lifetime = lifetime
            if entry.stop.is_set():
                raise OSError("Provider owner stopped before control transfer")
            # Set before the first write: a partial control frame is treated
            # conservatively if cancellation races its transfer.
            entry.request_started = True
        write_frame(process.stdin, payload)
        process.stdin.close()
        result = parse_outcome(read_frame(process.stdout), expected_request_id=payload["request"]["request_id"],
            expected_scope_hash=payload["binding"]["target_scope_hash"])
        if process.stdout.read(1):
            raise ValueError("unexpected extra Provider worker output")
        return result

    @staticmethod
    async def _reap(process, job, exchange, entry):
        failure = None
        try:
            if job is not None:
                try:
                    job.close()  # kills actual worker AND its venv redirector
                except OSError as error:
                    failure = error
            if process is not None:
                if process.poll() is None:
                    process.kill()
                await asyncio.to_thread(process.wait, timeout=5)
            if exchange is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(exchange), 3)
                except Exception:
                    pass
            with entry.lock:
                lifetime = entry.lifetime
            confirmed = process is None or (process.poll() is not None and lifetime is not None
                and await asyncio.to_thread(lifetime.wait, 5))
            with entry.lock:
                entry.exit_confirmed = confirmed
            if lifetime is not None and confirmed:
                lifetime.close()
            if failure is not None or (entry.request_started and not confirmed):
                raise OSError("Provider worker cleanup not confirmed")
        finally:
            if process is not None:
                for stream in (process.stdin, process.stdout):
                    if stream is not None:
                        stream.close()

    async def close(self):
        self._closed = True
        owners = self._owners - {asyncio.current_task()}
        for owner in owners:
            owner.cancel()
        if owners:
            await asyncio.gather(*owners, return_exceptions=True)
