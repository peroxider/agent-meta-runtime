"""Owner-only storage protection shared by credentials and snapshots."""

import os
from pathlib import Path
import stat

from ..domain.errors import ErrorCode, StableError
from .windows_security import is_owner_only, secure_owner_only


def secure_private_path(path: Path) -> None:
    path = Path(path)
    if path.is_symlink() or path.is_junction():
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="private storage cannot be a reparse point")
    if os.name == "nt":
        secure_owner_only(path)
    else:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def require_private_path(path: Path) -> None:
    path = Path(path)
    if path.is_symlink() or path.is_junction():
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="private storage cannot be a reparse point")
    metadata = path.stat()
    valid = is_owner_only(path) if os.name == "nt" else (
        metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == (0o700 if path.is_dir() else 0o600)
    )
    if not valid:
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="private storage permissions invalid")
