"""Two-phase Artifact upload staging (§41.46).

``BeginPut(expected_size, expected_sha256)`` returns a 256-bit random
staging handle — a secret; only its SHA-256 is stored server-side — with
the fixed 1 MiB chunk size and 1-hour expiry. ``put_chunk`` accepts only
sequential chunks starting at the current committed offset: the chunk hash
must match, a replay of the last committed chunk (same offset, same hash)
is idempotent, any other offset or differing content is rejected. Staging
survives disconnects and is purged after expiry by ``purge_expired``.
Finalization verifies total size/hash and hands off to
:class:`~agent_meta_runtime.adapters.cas.FilesystemCas` for atomic
publication; the handle is invalidated immediately after.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...adapters.cas import CHUNK_SIZE, FilesystemCas, StagedUpload
from ...domain.errors import ErrorCode, StableError

__all__ = ["STAGING_TTL_US", "ChunkedStaging", "StagingSession"]

STAGING_TTL_US = 3_600_000_000  # 1 hour (§41.46)


@dataclass(frozen=True, slots=True)
class StagingSession:
    """What BeginPut reports to the client."""

    staging_handle: str
    chunk_size: int
    expires_at_us: int


class ChunkedStaging:
    """Multi-chunk staging sessions on top of the canonical staging root."""

    def __init__(self, cas: FilesystemCas, *, now_us: Any) -> None:
        self._cas = cas
        self._dir = cas.staging_dir
        self._now_us = now_us
        self._lock = threading.Lock()

    # -- helpers -----------------------------------------------------------
    def _handle_hash(self, handle: str) -> str:
        if not isinstance(handle, str) or len(handle) != 64 or not handle.isalnum():
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed staging handle"
            )
        try:
            return hashlib.sha256(bytes.fromhex(handle)).hexdigest()
        except ValueError as exc:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="malformed staging handle"
            ) from exc

    def _meta_path(self, handle_hash: str) -> Path:
        return self._dir / f"chunked-{handle_hash}.json"

    def _data_path(self, handle_hash: str) -> Path:
        return self._dir / f"chunked-{handle_hash}.bin"

    def _load_meta(self, handle_hash: str) -> dict[str, Any]:
        try:
            raw = self._meta_path(handle_hash).read_bytes()
            meta = json.loads(raw.decode("utf-8"))
        except (FileNotFoundError, ValueError, UnicodeDecodeError) as exc:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="unknown staging handle"
            ) from exc
        if not isinstance(meta, dict):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="corrupt staging metadata"
            )
        return meta

    # -- protocol ----------------------------------------------------------
    def begin_put(
        self, *, expected_size: int, expected_sha256: str, now_us: int | None = None
    ) -> StagingSession:
        now = self._now_us() if now_us is None else now_us
        if expected_size < 0:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="negative expected size"
            )
        if len(expected_sha256) != 64 or not all(
            c in "0123456789abcdef" for c in expected_sha256
        ):
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT, message="expected_sha256 must be hex sha256"
            )
        handle = secrets.token_hex(32)  # 256-bit secret, shown once
        handle_hash = self._handle_hash(handle)
        meta = {
            "expected_size": expected_size,
            "expected_sha256": expected_sha256,
            "committed_offset": 0,
            "last_chunk_hash": "",
            "created_at_us": now,
            "expires_at_us": now + STAGING_TTL_US,
        }
        self._meta_path(handle_hash).write_text(json.dumps(meta, sort_keys=True))
        self._data_path(handle_hash).touch(mode=0o600)
        return StagingSession(
            staging_handle=handle, chunk_size=CHUNK_SIZE, expires_at_us=now + STAGING_TTL_US
        )

    def put_chunk(
        self,
        *,
        staging_handle: str,
        offset: int,
        data: bytes,
        chunk_sha256: str,
        now_us: int | None = None,
    ) -> int:
        """Append one chunk; returns the committed offset (idempotent)."""

        now = self._now_us() if now_us is None else now_us
        handle_hash = self._handle_hash(staging_handle)
        with self._lock:
            meta = self._load_meta(handle_hash)
            if meta["expires_at_us"] <= now:
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="staging handle expired"
                )
            committed = int(meta["committed_offset"])
            digest = hashlib.sha256(data).hexdigest()
            # Exact replay of the last committed chunk: it ends at the
            # committed offset and its content matches the recorded hash.
            if committed and offset + len(data) == committed and meta["last_chunk_hash"] == digest:
                return committed
            if offset != committed:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="chunk offset must equal the committed offset",
                    details={"offset": offset, "committed": committed},
                )
            if len(data) > CHUNK_SIZE:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT, message="chunk exceeds 1 MiB"
                )
            if digest != chunk_sha256:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT, message="chunk hash mismatch"
                )
            if committed + len(data) > int(meta["expected_size"]):
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT, message="chunk exceeds expected size"
                )
            with open(self._data_path(handle_hash), "r+b") as fd:
                fd.seek(committed)
                fd.write(data)
                fd.flush()
                os.fsync(fd.fileno())
            meta["committed_offset"] = committed + len(data)
            meta["last_chunk_hash"] = digest
            self._meta_path(handle_hash).write_text(json.dumps(meta, sort_keys=True))
            return int(meta["committed_offset"])

    def finalize(self, *, staging_handle: str, now_us: int | None = None) -> str:
        """Verify totals, publish into the CAS, invalidate the handle.

        Returns the CAS storage relpath of the published blob.
        """

        now = self._now_us() if now_us is None else now_us
        handle_hash = self._handle_hash(staging_handle)
        with self._lock:
            meta = self._load_meta(handle_hash)
            if meta["expires_at_us"] <= now:
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION, message="staging handle expired"
                )
            data_path = self._data_path(handle_hash)
            size = data_path.stat().st_size
            if size != int(meta["expected_size"]):
                raise StableError(
                    code=ErrorCode.FAILED_PRECONDITION,
                    message="staged size does not match expected size",
                    details={"actual": size, "expected": int(meta["expected_size"])},
                )
            digest = hashlib.sha256(data_path.read_bytes()).hexdigest()
            if digest != meta["expected_sha256"]:
                raise StableError(
                    code=ErrorCode.INTEGRITY_ERROR,
                    message="staged content hash mismatch",
                )
            staged = StagedUpload(
                staging_path=data_path, sha256=digest, size_bytes=size
            )
            relpath = self._cas.publish(staged, expected_sha256=digest)
            self._meta_path(handle_hash).unlink(missing_ok=True)
            return relpath

    def discard(self, *, staging_handle: str) -> None:
        handle_hash = self._handle_hash(staging_handle)
        with self._lock:
            self._meta_path(handle_hash).unlink(missing_ok=True)
            self._data_path(handle_hash).unlink(missing_ok=True)

    def purge_expired(self, now_us: int | None = None) -> int:
        """Remove expired sessions (§41.46: expiry cleanup is GC's job)."""

        now = self._now_us() if now_us is None else now_us
        purged = 0
        with self._lock:
            for meta_path in self._dir.glob("chunked-*.json"):
                try:
                    meta = json.loads(meta_path.read_text())
                    expired = int(meta.get("expires_at_us", 0)) <= now
                except (ValueError, OSError):
                    expired = True
                if expired:
                    meta_path.unlink(missing_ok=True)
                    data_path = meta_path.with_name(
                        meta_path.name[: -len(".json")] + ".bin"
                    )
                    data_path.unlink(missing_ok=True)
                    purged += 1
        return purged
