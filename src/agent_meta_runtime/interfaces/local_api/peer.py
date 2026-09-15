"""Local endpoint peer identity and path rules (§41.26, §41.49.1).

POSIX: the UDS lives at ``<data_dir>/run/agent-meta.sock`` with directory
mode 0700 and socket mode 0600, and peer credentials are read via
``SO_PEERCRED`` — a connection whose UID differs from the daemon UID is
closed before any Hello payload is processed. Windows: the Named Pipe name
is ``\\\\.\\pipe\\agent-meta-<sha256(canonical-data-dir)[0:16]>`` and the
client SID must equal the daemon owner SID (checked on that platform;
marked no-cover here).
"""

from __future__ import annotations

import hashlib
import os
import socket
import stat
import struct
from pathlib import Path

from ...domain.errors import ErrorCode, StableError

__all__ = [
    "SOCKET_MODE",
    "pipe_name_for_data_dir",
    "prepare_socket_dir",
    "require_same_uid",
    "socket_path_for_data_dir",
    "write_endpoint_file",
]

SOCKET_MODE = 0o600


def socket_path_for_data_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "run" / "agent-meta.sock"


def pipe_name_for_data_dir(data_dir: Path) -> str:  # pragma: no cover - Windows
    digest = hashlib.sha256(str(Path(data_dir).resolve()).encode()).hexdigest()
    return f"\\\\.\\pipe\\agent-meta-{digest[:16]}"


def require_same_uid(sock: socket.socket, daemon_uid: int) -> int:
    """Read SO_PEERCRED and enforce peer UID == daemon UID (§41.49.1)."""

    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", creds[:12])  # struct ucred: pid, uid, gid
    except OSError as exc:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION, message="no peer identity"
        ) from exc
    if uid != daemon_uid:
        raise StableError(
            code=ErrorCode.FAILED_PRECONDITION, message="peer identity mismatch"
        )
    return uid


def prepare_socket_dir(data_dir: Path) -> Path:
    run_dir = Path(data_dir) / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, stat.S_IRWXU)  # 0700
    return run_dir


def write_endpoint_file(
    data_dir: Path,
    *,
    transport: str,
    address: str,
    pid: int,
    instance_id: str,
    api_version: str,
    started_at_us: int,
) -> Path:
    """Persist endpoint discovery metadata (no secrets, §41.26)."""

    path = Path(data_dir) / "run" / "endpoint.json"
    payload = (
        "{"
        + ", ".join(
            f'"{k}": "{v}"'
            if isinstance(v, str)
            else f'"{k}": {v}'
            for k, v in {
                "transport": transport,
                "address": address,
                "pid": pid,
                "instance_id": instance_id,
                "api_version": api_version,
                "started_at_us": started_at_us,
            }.items()
        )
        + "}"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(payload)
    os.chmod(path, 0o600)
    return path
