"""Portable workspaces, quota, minimal environment, output caps (§41.48.1).

Workspaces live under ``<data_dir>/workspaces/<realm-hash-16>/<workspace-uuid>/``
and only relative paths reach any DB. Task workloads default to a 512 MiB
quota, Scratch/Candidate to 1 GiB, checked before and after writes; exceeding
the quota is ``RESOURCE_EXHAUSTED`` and stops later effects. The worker
environment keeps only controlled PATH entries, locale/timezone, request and
workspace handles, and an explicit allowlist — provider keys, root
credentials, home overrides, proxy, ``PYTHONPATH`` and dynamic-loader
variables are never inherited. stdout/stderr are capped at 8 MiB with
head-4-MiB + tail-4-MiB retention and an ``output_truncated`` flag.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Any

from ...domain.errors import ErrorCode, StableError

__all__ = [
    "SCRATCH_QUOTA_BYTES",
    "TASK_QUOTA_BYTES",
    "OutputCapture",
    "build_worker_env",
    "check_quota",
    "workspace_directory",
]

TASK_QUOTA_BYTES = 512 * 1024 * 1024
SCRATCH_QUOTA_BYTES = 1024 * 1024 * 1024

_OUTPUT_CAP = 8 * 1024 * 1024
_HEAD = 4 * 1024 * 1024
_TAIL = 4 * 1024 * 1024

# Never inherited by the worker (§41.48.1).
_DROP_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "OPENAI_",
    "ANTHROPIC_",
)
_DROP_ENV_KEYS = {
    "SYSTEMROOT",
    "WINDIR",
    "HOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
}
_DROP_ENV_SUFFIXES = ("_PROXY", "_proxy")


def realm_hash(realm_id: str) -> str:
    """First 16 hex chars of the realm-id SHA-256 (path-safe shard)."""

    return hashlib.sha256(realm_id.encode("utf-8")).hexdigest()[:16]


def workspace_directory(data_dir: Path, realm_id: str, workspace_id: str) -> Path:
    """Workspace path; ``workspace_id`` must be a UUID (validated, not raw)."""

    try:
        uuid.UUID(workspace_id)
    except ValueError as exc:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="workspace id must be a UUID"
        ) from exc
    return Path(data_dir) / "workspaces" / realm_hash(realm_id) / workspace_id


def directory_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def check_quota(workspace: Path, limit_bytes: int, *, additional: int = 0) -> int:
    """Current usage vs quota (checked before and after writes); raises
    ``RESOURCE_EXHAUSTED`` and callers must stop subsequent effects."""

    usage = directory_size(workspace) + additional
    if usage > limit_bytes:
        raise StableError(
            code=ErrorCode.RESOURCE_EXHAUSTED,
            message="workspace quota exceeded",
            details={"usage_bytes": usage, "limit_bytes": limit_bytes},
        )
    return usage


def build_worker_env(
    *,
    runtime_paths: list[str],
    request_id: str,
    workspace_relpath: str,
    allowlist: dict[str, str] | None = None,
) -> dict[str, str]:
    """Minimal worker environment (§41.48.1).

    Only controlled runtime PATH entries, locale/timezone, request/workspace
    handles and the explicit allowlist survive; the parent's provider keys,
    proxy settings, HOME override, Python path and loader variables do not.
    """

    env = {
        "PATH": os.pathsep.join(runtime_paths),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "TZ": os.environ.get("TZ", "UTC"),
        "AGENT_META_REQUEST_ID": request_id,
        "AGENT_META_WORKSPACE": workspace_relpath,
    }
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        kernel.GetWindowsDirectoryW.restype = wintypes.UINT
        directory = ctypes.create_unicode_buffer(32768)
        length = kernel.GetWindowsDirectoryW(directory, len(directory))
        if not 0 < length < len(directory):
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message='Windows system directory is unavailable')
        # Winsock provider loading needs the OS directory even in a minimal
        # environment. Query it from Windows rather than accept an override.
        env['SystemRoot'] = env['WINDIR'] = directory.value
    for key, value in (allowlist or {}).items():
        normalized = key.upper()
        if normalized in _DROP_ENV_KEYS or normalized.startswith(_DROP_ENV_PREFIXES) or any(
            normalized.endswith(s) for s in _DROP_ENV_SUFFIXES
        ):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message=f"allowlist key is not permitted: {key}",
            )
        env[key] = value
    return env


class OutputCapture:
    """Bounded stdout/stderr capture (§41.48.1).

    Reads keep draining (no pipe deadlock) once the 8 MiB cap is hit, but only
    the first 4 MiB and last 4 MiB are retained and ``output_truncated`` is
    set. Structured results never travel through stdout.
    """

    def __init__(self) -> None:
        self._data = bytearray()
        self.truncated = False
        self.dropped = 0

    def feed(self, chunk: bytes) -> None:
        if len(self._data) + len(chunk) <= _OUTPUT_CAP:
            self._data.extend(chunk)
            return
        # Over the cap: retain head, keep draining, remember the tail window.
        room_head = max(_HEAD - len(self._data), 0)
        if room_head:
            self._data.extend(chunk[:room_head])
            chunk = chunk[room_head:]
        self.truncated = True
        self.dropped += len(chunk)
        combined = bytes(self._data[_HEAD:]) + chunk
        self._data = self._data[:_HEAD] + combined[-_TAIL:]

    def bytes_value(self) -> bytes:
        return bytes(self._data)

    def snapshot(self) -> dict[str, Any]:
        return {
            "size_bytes": len(self._data),
            "output_truncated": self.truncated,
            "dropped_bytes": self.dropped,
        }
