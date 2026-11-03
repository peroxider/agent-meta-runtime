"""Step 04 tests: frozen wire layer semantics (§41.41, §41.14, §41.27)."""

from __future__ import annotations

import hashlib

import pytest

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols import backend_wire as wire
from agent_meta_runtime.protocols._v1 import execution_backend_pb2 as eb
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport


def test_payload_hash_is_lowercase_sha256() -> None:
    payload = b'{"a":1}'
    assert wire.payload_hash(payload) == hashlib.sha256(payload).hexdigest()
    assert wire.payload_hash(payload) == wire.payload_hash(payload).lower()


def test_backend_methods_registry_frozen() -> None:
    assert wire.BACKEND_METHODS == (
        "agent_meta.execution_backend.v1.Backend.Negotiate",
        "agent_meta.execution_backend.v1.Backend.Submit",
        "agent_meta.execution_backend.v1.Backend.Await",
        "agent_meta.execution_backend.v1.Backend.Cancel",
        "agent_meta.execution_backend.v1.Backend.Inspect",
        "agent_meta.execution_backend.v1.Backend.Reconcile",
        "agent_meta.execution_backend.v1.Backend.AcknowledgeTerminal",
        "agent_meta.execution_backend.v1.Backend.CloseSession",
    )


def test_envelope_request_id_is_uuidv7_and_echoed() -> None:
    envelope = wire.build_envelope(method=wire.BACKEND_METHODS[0], payload=b"x")
    assert envelope.protocol_major == 1
    assert envelope.request_id
    echo = wire.build_envelope(
        method=wire.BACKEND_METHODS[0], payload=b"y", is_response=True,
        request_id=envelope.request_id,
    )
    assert echo.request_id == envelope.request_id


def test_envelope_rejects_payload_and_error() -> None:
    error = wire.error_to_rpc(StableError(code=ErrorCode.INVALID_ARGUMENT, message="x"))
    with pytest.raises(StableError) as exc:
        wire.build_envelope(method="m", payload=b"x", error=error)
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT


def test_trace_map_only_traceparent_tracestate() -> None:
    ok = wire.validate_trace({"traceparent": "00-trace-span-01", "tracestate": "x"})
    assert ok == {"traceparent": "00-trace-span-01", "tracestate": "x"}
    with pytest.raises(StableError) as exc:
        wire.validate_trace({"bogus": "1"})
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    assert exc.value.details["keys"] == ["bogus"]


def test_error_round_trip_and_conditional_retryable() -> None:
    original = StableError(
        code=ErrorCode.DEADLINE_EXCEEDED,
        message="late",
        details={"status": "RUNNING"},
    )
    rpc = wire.error_to_rpc(original)
    rebuilt = wire.error_from_rpc(rpc)
    assert rebuilt.code == ErrorCode.DEADLINE_EXCEEDED
    assert rebuilt.message == "late"
    assert rebuilt.details == {"status": "RUNNING", "retryable_hint": "conditional"}


def test_error_from_rpc_unknown_code_fails() -> None:
    rpc = transport.RpcError(code="TOTALLY_UNKNOWN", message_safe="m")
    with pytest.raises(StableError) as exc:
        wire.error_from_rpc(rpc)
    assert exc.value.code == ErrorCode.INTERNAL


def test_authority_token_redacts_everything() -> None:
    token = wire.AuthorityToken(b"secret-bytes")
    assert repr(token) == "[REDACTED]"
    assert str(token) == "[REDACTED]"
    assert token == wire.AuthorityToken(b"secret-bytes")
    assert token != wire.AuthorityToken(b"other")
    assert b"secret" not in repr(token).encode()


def test_negotiate_version_intersection() -> None:
    ranges = [transport.VersionRange(major=1, min_minor=0, max_minor=0)]
    assert wire.negotiate_version(ranges, server_major=1, server_minor=3) == (1, 0)
    ranges = [transport.VersionRange(major=1, min_minor=1, max_minor=9)]
    assert wire.negotiate_version(ranges, server_major=1, server_minor=3) == (1, 3)
    ranges = [transport.VersionRange(major=2, min_minor=0, max_minor=0)]
    with pytest.raises(StableError) as exc:
        wire.negotiate_version(ranges, server_major=1, server_minor=0)
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    ranges = [transport.VersionRange(major=1, min_minor=5, max_minor=9)]
    with pytest.raises(StableError):
        wire.negotiate_version(ranges, server_major=1, server_minor=2)


def test_select_features_never_fakes_unsupported() -> None:
    available = {"process": "SUPPORTED", "network_isolation": "UNSUPPORTED"}
    required, optional = wire.select_features(
        ["process"], ["network_isolation", "workspace"], available
    )
    assert required == {"process"}
    assert optional == set()
    with pytest.raises(StableError) as exc:
        wire.select_features(["network_isolation"], [], available)
    assert exc.value.code == ErrorCode.FEATURE_UNAVAILABLE
    assert exc.value.details["feature"] == "network_isolation"
    assert exc.value.details["reported"] == "UNSUPPORTED"


def test_execution_request_authority_token_field_present() -> None:
    request = eb.ExecutionRequest(session_id="s", authority_token=b"tok")
    assert request.authority_token == b"tok"
    # field number 12 on the wire
    assert b"\x62" in request.SerializeToString()
