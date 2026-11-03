"""Platform process-tree cancellation (§41.48.3).

Ladder: GRACEFUL (control-channel cancel file) → wait 5 s → SIGTERM to the
process group → wait 5 s → SIGKILL. Every step re-inspects the worker
identity (PID + process-start identity) before signalling, so a recycled PID
is never targeted. ``terminal_confirmed`` is true only once the process tree
exit has actually been observed. On Windows the worker runs inside a Job
Object with kill-on-job-close; the ladder degrades to control-cancel then
``TerminateJobObject``.
"""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path
from typing import Any, Callable

from ...domain.canonical import canonical_json
from . import worker as _worker

__all__ = ["cancel_process_tree", "signal_process_group", "write_control_cancel"]

GRACEFUL_WAIT_S = 5.0
TERM_WAIT_S = 5.0
_CONTROL_CANCEL = "control.cancel"


def write_control_cancel(request_dir: Path) -> None:
    """GRACEFUL step: cooperative cancel via the worker control channel."""

    (request_dir / _CONTROL_CANCEL).write_bytes(canonical_json({"cancel": True}))


def _identity_alive(pid: int, start_identity: str) -> bool:
    current = _worker.process_start_identity(pid)
    return current == start_identity


def signal_process_group(pid: int, start_identity: str, sig: int) -> bool:
    """Signal the worker's process group after identity re-inspection.

    Returns True when the signal was delivered; False when the process
    already exited (or the PID was recycled — never signalled).
    """

    if not _identity_alive(pid, start_identity):
        return False
    pgid = os.getpgid(pid)  # worker started with a new session/pgid
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return False
    return True


def _wait_exit(
    pid: int,
    start_identity: str,
    timeout_s: float,
    reap: Callable[[], None] | None = None,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if reap is not None:
            reap()  # reap the exited child so /proc stops showing it
        if not _identity_alive(pid, start_identity):
            return True
        time.sleep(0.05)
    if reap is not None:
        reap()
    return not _identity_alive(pid, start_identity)


def _cancel_posix(
    request_dir: Path,
    pid: int,
    start_identity: str,
    reap: Callable[[], None] | None = None,
) -> tuple[bool, dict[str, Any]]:
    steps: list[str] = []
    write_control_cancel(request_dir)
    steps.append("control_cancel")
    if _wait_exit(pid, start_identity, GRACEFUL_WAIT_S, reap):
        return True, {"steps": steps}
    if signal_process_group(pid, start_identity, signal.SIGTERM):
        steps.append("SIGTERM")
        if _wait_exit(pid, start_identity, TERM_WAIT_S, reap):
            return True, {"steps": steps}
    if signal_process_group(pid, start_identity, signal.SIGKILL):
        steps.append("SIGKILL")
        if _wait_exit(pid, start_identity, GRACEFUL_WAIT_S, reap):
            return True, {"steps": steps}
    return False, {"steps": steps}


def _cancel_windows(
    request_dir: Path, pid: int, start_identity: str, windows_job=None, reap=None
) -> tuple[bool, dict[str, Any]]:  # pragma: no cover - exercised on Windows
    """Windows ladder: control cancel → TerminateJobObject (kill-on-close)."""

    steps: list[str] = []
    if windows_job is None:
        return False, {'steps':steps,'reason':'OWNED_JOB_UNAVAILABLE'}
    if not _identity_alive(pid, start_identity) or not windows_job.contains(pid):
        return windows_job.active_processes == 0, {'steps':steps,'reason':'WORKER_IDENTITY_UNAVAILABLE'}
    write_control_cancel(request_dir)
    steps.append("control_cancel")
    if windows_job.wait_empty(GRACEFUL_WAIT_S, reap):
        return True, {"steps": steps}
    # The retained Job handle identifies this exact owned tree even if its
    # original leader exited during the graceful wait. Never treat a process
    # handle as a Job or choose another process from a reused PID.
    windows_job.terminate()
    steps.append('TerminateJobObject')
    if windows_job.wait_empty(TERM_WAIT_S, reap):
        return True, {'steps':steps}
    return False, {"steps": steps}


def cancel_process_tree(
    request_dir: Path,
    pid: int,
    start_identity: str,
    *,
    mode: str = "GRACEFUL",
    reap: Callable[[], None] | None = None,
    windows_job=None,
) -> tuple[bool, dict[str, Any]]:
    """Run the cancellation ladder; returns ``(terminal_confirmed, details)``.

    ``terminal_confirmed`` is true only when the worker process tree exit was
    observed; a forced cancellation that cannot be confirmed leaves the
    effect state UNKNOWN upstream (fail closed). ``reap`` lets the caller
    (the parent holding the ``Popen``) collect the exited child so liveness
    checks stop seeing the zombie.
    """

    if os.name == "nt":  # pragma: no cover - exercised on Windows
        try:
            confirmed, details = _cancel_windows(request_dir, pid, start_identity, windows_job, reap)
        except OSError:
            confirmed, details = False, {'steps':[], 'reason':'OWNED_JOB_CONFIRMATION_UNAVAILABLE'}
    else:
        confirmed, details = _cancel_posix(request_dir, pid, start_identity, reap)
    if mode == "FORCE" and confirmed:
        details["forced"] = True
    return confirmed, details
