"""Step 06 gate: two-phase chunked artifact staging (§41.46)."""

from __future__ import annotations

import hashlib

import pytest

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.interfaces.local_api.staging import STAGING_TTL_US, ChunkedStaging

NOW = 1_000_000_000


def _staging(tmp_path, now=NOW):
    cas = FilesystemCas(tmp_path)
    return ChunkedStaging(cas, now_us=lambda: now), cas


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_begin_put_returns_secret_handle_and_chunk_size(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"hello world"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    assert len(session.staging_handle) == 64  # 256-bit secret, hex
    assert session.chunk_size == 1 << 20
    assert session.expires_at_us == NOW + STAGING_TTL_US


def test_put_and_finalize_publishes_blob(tmp_path):
    staging, cas = _staging(tmp_path)
    data = b"x" * 10
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    committed = staging.put_chunk(
        staging_handle=session.staging_handle,
        offset=0,
        data=data,
        chunk_sha256=_digest(data),
    )
    assert committed == len(data)
    relpath = staging.finalize(staging_handle=session.staging_handle)
    assert (cas.artifacts_dir / relpath).read_bytes() == data


def test_replayed_last_chunk_is_idempotent(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"chunk-data"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    first = staging.put_chunk(
        staging_handle=session.staging_handle, offset=0, data=data, chunk_sha256=_digest(data)
    )
    replay = staging.put_chunk(
        staging_handle=session.staging_handle, offset=0, data=data, chunk_sha256=_digest(data)
    )
    assert first == replay == len(data)


def test_wrong_offset_rejected(tmp_path):
    staging, _ = _staging(tmp_path)
    session = staging.begin_put(expected_size=10, expected_sha256=_digest(b"0123456789"))
    with pytest.raises(StableError) as excinfo:
        staging.put_chunk(
            staging_handle=session.staging_handle,
            offset=5,
            data=b"01234",
            chunk_sha256=_digest(b"01234"),
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_chunk_hash_mismatch_rejected(tmp_path):
    staging, _ = _staging(tmp_path)
    session = staging.begin_put(expected_size=4, expected_sha256=_digest(b"body"))
    with pytest.raises(StableError) as excinfo:
        staging.put_chunk(
            staging_handle=session.staging_handle,
            offset=0,
            data=b"body",
            chunk_sha256=_digest(b"other"),
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_chunk_over_expected_size_rejected(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"abc"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    with pytest.raises(StableError) as excinfo:
        staging.put_chunk(
            staging_handle=session.staging_handle,
            offset=0,
            data=b"abcd",
            chunk_sha256=_digest(b"abcd"),
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_finalize_size_and_hash_verification(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"abcdef"
    session = staging.begin_put(expected_size=len(data) + 1, expected_sha256=_digest(data))  # size lie
    staging.put_chunk(
        staging_handle=session.staging_handle, offset=0, data=data, chunk_sha256=_digest(data)
    )
    with pytest.raises(StableError) as excinfo:
        staging.finalize(staging_handle=session.staging_handle)
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION

    staging2, _ = _staging(tmp_path)
    session = staging2.begin_put(expected_size=len(data), expected_sha256="f" * 64)  # hash lie
    staging2.put_chunk(
        staging_handle=session.staging_handle, offset=0, data=data, chunk_sha256=_digest(data)
    )
    with pytest.raises(StableError) as excinfo:
        staging2.finalize(staging_handle=session.staging_handle)
    assert excinfo.value.code == ErrorCode.INTEGRITY_ERROR


def test_handle_invalidated_after_finalize(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"once"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    staging.put_chunk(
        staging_handle=session.staging_handle, offset=0, data=data, chunk_sha256=_digest(data)
    )
    staging.finalize(staging_handle=session.staging_handle)
    with pytest.raises(StableError) as excinfo:
        staging.finalize(staging_handle=session.staging_handle)
    assert excinfo.value.code == ErrorCode.NOT_FOUND


def test_malformed_handle_rejected(tmp_path):
    staging, _ = _staging(tmp_path)
    for handle in ("", "short", "g" * 64, "z" * 63):
        with pytest.raises(StableError) as excinfo:
            staging.finalize(staging_handle=handle)
        assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_expired_session_rejected_and_purged(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"old"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    future = NOW + STAGING_TTL_US + 1
    with pytest.raises(StableError) as excinfo:
        staging.put_chunk(
            staging_handle=session.staging_handle,
            offset=0,
            data=data,
            chunk_sha256=_digest(data),
            now_us=future,
        )
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION
    assert staging.purge_expired(now_us=future) == 1
    assert staging.purge_expired(now_us=future) == 0


def test_discard_removes_session(tmp_path):
    staging, _ = _staging(tmp_path)
    data = b"drop"
    session = staging.begin_put(expected_size=len(data), expected_sha256=_digest(data))
    staging.discard(staging_handle=session.staging_handle)
    with pytest.raises(StableError):
        staging.finalize(staging_handle=session.staging_handle)
