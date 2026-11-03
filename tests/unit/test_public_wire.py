"""Step 06 gate: Public API v1 wire layer (§41.26, §41.52)."""

from __future__ import annotations

import struct

import pytest

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.protocols._v1 import public_pb2 as pub
from agent_meta_runtime.protocols._v1 import transport_pb2 as transport
from agent_meta_runtime.protocols.public_wire import (
    MAX_FRAME_BYTES,
    METHODS,
    PUBLIC_API_MAJOR,
    decode_frame_length,
    encode_frame,
    parse_envelope,
)


def test_methods_registry_covers_public_v1_groups():
    methods = dict(METHODS)
    for name in (
        "agent_meta.public.v1.Runtime.GetInfo",
        "agent_meta.public.v1.Task.Submit",
        "agent_meta.public.v1.Artifact.BeginPut",
        "agent_meta.public.v1.Composition.Validate",
        "agent_meta.public.v1.Graph.Why",
    ):
        assert name in methods
        request, response = methods[name]
        assert callable(request)
        assert callable(response)
    # every registered response/request class is a public (not transport) message
    for request, response in methods.values():
        assert request.__module__.endswith("public_pb2")
        assert response.__module__.endswith("public_pb2")


def test_frame_roundtrip_and_big_endian_layout():
    payload = b"\x01\x02\x03"
    frame = encode_frame(payload)
    assert frame[:1] == b"\x00" and frame[3:4] == b"\x03"  # >I big endian
    assert decode_frame_length(frame[:4]) == 3


def test_encode_rejects_frame_over_16mib():
    with pytest.raises(StableError) as excinfo:
        encode_frame(b"x" * (MAX_FRAME_BYTES + 1))
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_decode_validates_length_before_allocation():
    header = struct.pack(">I", MAX_FRAME_BYTES + 1)
    with pytest.raises(StableError) as excinfo:
        decode_frame_length(header)
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_decode_rejects_short_header():
    with pytest.raises(StableError):
        decode_frame_length(b"\x00\x01")


def test_parse_envelope_rejects_malformed_body():
    with pytest.raises(StableError) as excinfo:
        parse_envelope(b"\xff\xff\xff\xff not protobuf")
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT


def test_parse_envelope_roundtrip():
    envelope = transport.RpcEnvelope(
        protocol_major=PUBLIC_API_MAJOR,
        request_id="abc",
        method="agent_meta.public.v1.Runtime.GetInfo",
    )
    envelope.payload = pub.GetInfoRequest().SerializeToString()
    parsed = parse_envelope(envelope.SerializeToString())
    assert parsed.request_id == "abc"
    assert parsed.HasField("payload")
