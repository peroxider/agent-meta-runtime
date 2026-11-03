"""Step 06 gate: HMAC cursor authentication (§41.52)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.application.cursor import DEFAULT_CURSOR_TTL_US, CursorCodec
from agent_meta_runtime.domain.errors import ErrorCode, StableError

KEY = b"k" * 32
NOW = 1_000_000_000


def test_issue_verify_roundtrip():
    codec = CursorCodec(session_key=KEY)
    token = codec.issue(
        kind="list.tasks", snapshot_revision=7, last_key="task://x", now_us=NOW
    )
    payload = codec.verify(token, kind="list.tasks", now_us=NOW + 1)
    assert payload["snapshot_revision"] == 7
    assert payload["last_key"] == "task://x"
    assert payload["expiry_us"] == NOW + DEFAULT_CURSOR_TTL_US


def test_tampered_payload_fails_authentication():
    codec = CursorCodec(session_key=KEY)
    token = codec.issue(
        kind="list.tasks", snapshot_revision=1, last_key="a", now_us=NOW
    )
    prefix, body, tag = token.split(".")
    body = body[:-2] + ("AA" if body[-2:] != "AA" else "BB")
    with pytest.raises(StableError) as excinfo:
        codec.verify(f"{prefix}.{body}.{tag}", kind="list.tasks", now_us=NOW)
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_tampered_tag_fails_authentication():
    codec = CursorCodec(session_key=KEY)
    token = codec.issue(kind="list.tasks", snapshot_revision=1, last_key="a", now_us=NOW)
    forged = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(StableError):
        codec.verify(forged, kind="list.tasks", now_us=NOW)


def test_cross_query_kind_rejected():
    codec = CursorCodec(session_key=KEY)
    token = codec.issue(kind="list.tasks", snapshot_revision=1, last_key="a", now_us=NOW)
    with pytest.raises(StableError) as excinfo:
        codec.verify(token, kind="list.artifacts", now_us=NOW)
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_expired_cursor_rejected():
    codec = CursorCodec(session_key=KEY, ttl_us=1_000)
    token = codec.issue(kind="why", snapshot_revision=1, last_key="a", now_us=NOW)
    with pytest.raises(StableError) as excinfo:
        codec.verify(token, kind="why", now_us=NOW + 2_000)
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_malformed_tokens_rejected():
    codec = CursorCodec(session_key=KEY)
    for token in ("", "amcursor1", "amcursor1.a.b.c", "other.abc.def"):
        with pytest.raises(StableError) as excinfo:
            codec.verify(token, kind="list.tasks", now_us=NOW)
        assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_budget_and_frontier_are_bound_into_payload():
    codec = CursorCodec(session_key=KEY)
    token = codec.issue(
        kind="why",
        snapshot_revision=3,
        last_key="n",
        now_us=NOW,
        frontier_hash="fr",
        budget={"max_nodes": 5},
    )
    payload = codec.verify(token, kind="why", now_us=NOW)
    assert payload["frontier_hash"] == "fr"
    assert payload["budget"] == {"max_nodes": 5}
