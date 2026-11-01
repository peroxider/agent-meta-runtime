"""Single-writer daemon lock (§41.39.2).

``<data_dir>/run/daemon.lock`` is an OS advisory exclusive lock; ownership is
proven by holding the file lock, never by reading a PID. Lock file content
records instance id, pid, process start identity and endpoint.
"""

from __future__ import annotations

import errno
import json
import os
from dataclasses import dataclass
from pathlib import Path

from ..domain.canonical import now_us
from ..domain.errors import ErrorCode, StableError

__all__ = ["AlreadyRunning", "DaemonLock", "DaemonLockInfo", "acquire_daemon_lock"]

# Windows byte-range locks are mandatory: locking the metadata's first byte
# prevents even read-only discovery. Reserve a separate byte beyond the bounded
# metadata region, while every writer still competes for the same OS lock.
_WINDOWS_LOCK_OFFSET = 1 << 20


class AlreadyRunning(StableError):
    """Raised when the data directory already has a live daemon owner."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(
            code=ErrorCode.ALREADY_RUNNING,
            message=message,
            details=details or {},
        )


def _process_start_identity() -> str:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
            raise ctypes.WinError(ctypes.get_last_error())
        return f"windows-filetime:{(creation.dwHighDateTime << 32) | creation.dwLowDateTime}"
    # Best-effort identity distinguishing process incarnations with the same
    # PID across restarts. Linux exposes starttime via /proc.
    try:
        stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
        return stat.split(") ", 1)[1].split()[19]  # field 22: starttime
    except (OSError, IndexError):
        return ""


@dataclass(frozen=True, slots=True)
class DaemonLockInfo:
    instance_id: str
    pid: int
    process_start_identity: str
    endpoint: str
    created_at_us: int

    def to_json(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "pid": self.pid,
            "process_start_identity": self.process_start_identity,
            "endpoint": self.endpoint,
            "created_at_us": self.created_at_us,
        }


class DaemonLock:
    """Advisory exclusive lock held for the lifetime of the daemon."""

    __slots__ = ("_path", "_fd", "_info")

    def __init__(self, path: Path, fd: int, info: DaemonLockInfo) -> None:
        self._path = path
        self._fd = fd
        self._info = info

    @property
    def path(self) -> Path:
        return self._path

    @property
    def info(self) -> DaemonLockInfo:
        return self._info

    def release(self) -> None:
        if self._fd < 0:
            return
        try:
            _unlock_fd(self._fd)
        finally:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "DaemonLock":
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def _lock_fd(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        os.lseek(fd, 0, os.SEEK_SET)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_fd(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


def acquire_daemon_lock(data_dir: Path, endpoint: str, instance_id: str) -> DaemonLock:
    """Acquire the single-writer lock or raise ``AlreadyRunning`` (exit code 12)."""

    run_dir = data_dir / "run"
    if run_dir.is_symlink() or run_dir.is_junction():
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="daemon run directory cannot be a reparse point")
    run_dir.mkdir(parents=True, exist_ok=True)
    lock_path = run_dir / "daemon.lock"
    if lock_path.is_symlink() or lock_path.is_junction():
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="daemon lock cannot be a reparse point")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _lock_fd(fd)
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
            owner = _read_lock_owner(lock_path)
            raise AlreadyRunning(
                "another daemon owns this data directory",
                {"lock_path": str(lock_path), "owner_pid": owner.get("pid")},
            ) from exc
        raise
    try:
        os.ftruncate(fd, 0)
        info = DaemonLockInfo(
            instance_id=instance_id,
            pid=os.getpid(),
            process_start_identity=_process_start_identity(),
            endpoint=endpoint,
            created_at_us=now_us(),
        )
        metadata = json.dumps(info.to_json()).encode("utf-8")
        if len(metadata) >= _WINDOWS_LOCK_OFFSET:
            raise OSError("daemon endpoint metadata exceeds reserved region")
        os.write(fd, metadata)
    except OSError:
        _unlock_fd(fd)
        os.close(fd)
        raise
    return DaemonLock(lock_path, fd, info)


def _read_lock_owner(lock_path: Path) -> dict:
    try:
        return json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
