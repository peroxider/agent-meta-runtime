"""Filesystem content-addressed Artifact Store (§41.7).

Layout under the data directory::

    artifacts/sha256/ab/cd/<full-hash>
    staging/<uuid>.tmp

Writes go staging -> hash/size verify -> fsync -> atomic rename -> directory
fsync. If the target already exists it is verified and reused, so committed
artifacts are immutable. Opening a blob always re-verifies path, size and
full SHA-256; symlinks and path traversal are rejected.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..domain.errors import ErrorCode, StableError

__all__ = ["FilesystemCas", "StagedUpload"]

CHUNK_SIZE = 1 << 20


def _integrity_error(message: str, **details: object) -> StableError:
    return StableError(
        code=ErrorCode.INTEGRITY_ERROR, message=message, details=details
    )


@dataclass(frozen=True)
class StagedUpload:
    staging_path: Path
    sha256: str
    size_bytes: int


class FilesystemCas:
    """CAS rooted at ``root`` (the data directory containing artifacts/)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.artifacts_dir = self.root / "artifacts"
        self.staging_dir = self.root / "staging"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    # -- helpers -----------------------------------------------------------
    def relpath_for(self, sha256_hex: str) -> str:
        return f"sha256/{sha256_hex[:2]}/{sha256_hex[2:4]}/{sha256_hex}"

    def absolute_path(self, storage_relpath: str) -> Path:
        """Resolve a stored relpath, rejecting traversal and symlinks."""

        if storage_relpath.startswith("/") or ".." in storage_relpath.split("/"):
            raise _integrity_error(
                "storage relpath must be relative and normalized",
                storage_relpath=storage_relpath,
            )
        target = self.artifacts_dir / storage_relpath
        resolved_root = self.artifacts_dir.resolve()
        resolved = target.resolve()
        if resolved_root != resolved and resolved_root not in resolved.parents:
            raise _integrity_error(
                "storage relpath escapes the artifact root",
                storage_relpath=storage_relpath,
            )
        current = self.artifacts_dir
        for part in Path(storage_relpath).parts:
            current = current / part
            if current.is_symlink():
                raise _integrity_error("symlink in artifact path", path=str(current))
        return target

    def _fsync_dir(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    # -- write path --------------------------------------------------------
    def stage(self, data: bytes) -> StagedUpload:
        """Write bytes to a unique staging file, hashing while writing."""

        digest = hashlib.sha256()
        staging_path = self.staging_dir / f"{uuid.uuid4().hex}.tmp"
        size = 0
        fd = os.open(staging_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            for offset in range(0, len(data), CHUNK_SIZE):
                chunk = data[offset : offset + CHUNK_SIZE]
                os.write(fd, chunk)
                digest.update(chunk)
                size += len(chunk)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            staging_path.unlink(missing_ok=True)
            raise
        os.close(fd)
        return StagedUpload(
            staging_path=staging_path, sha256=digest.hexdigest(), size_bytes=size
        )

    def publish(self, staged: StagedUpload, expected_sha256: str | None = None) -> str:
        """Verify then atomically publish; returns the storage relpath."""

        if expected_sha256 is not None and staged.sha256 != expected_sha256:
            staged.staging_path.unlink(missing_ok=True)
            raise _integrity_error(
                "staged content hash mismatch",
                expected=expected_sha256,
                actual=staged.sha256,
            )
        relpath = self.relpath_for(staged.sha256)
        target = self.absolute_path(relpath)
        if target.exists():
            if not target.is_symlink() and self._verify_file(
                target, staged.sha256, staged.size_bytes
            ):
                staged.staging_path.unlink(missing_ok=True)
                return relpath
            raise _integrity_error(
                "existing artifact content does not match its address",
                storage_relpath=relpath,
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        os.rename(staged.staging_path, target)
        self._fsync_dir(target.parent)
        return relpath

    def put(self, data: bytes, expected_sha256: str | None = None) -> str:
        staged = self.stage(data)
        try:
            return self.publish(staged, expected_sha256)
        except BaseException:
            staged.staging_path.unlink(missing_ok=True)
            raise

    # -- read path ---------------------------------------------------------
    @staticmethod
    def _verify_file(path: Path, sha256_hex: str, size_bytes: int) -> bool:
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
        return size == size_bytes and digest.hexdigest() == sha256_hex

    def open_blob(
        self, storage_relpath: str, sha256_hex: str, size_bytes: int
    ) -> bytes:
        """Read a blob, verifying path, size and full SHA-256 (§41.7)."""

        path = self.absolute_path(storage_relpath)
        if not path.is_file():
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="artifact blob missing from CAS",
                details={"storage_relpath": storage_relpath},
            )
        data = path.read_bytes()
        if len(data) != size_bytes or hashlib.sha256(data).hexdigest() != sha256_hex:
            raise _integrity_error(
                "artifact blob failed integrity verification",
                storage_relpath=storage_relpath,
            )
        return data
