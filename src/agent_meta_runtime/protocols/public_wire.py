"""Public API v1 wire layer (§41.26, §41.41, §41.52): method registry,
4-byte big-endian framing and per-connection/server limits.

The generated module :mod:`agent_meta_runtime.protocols._v1.public_pb2`
carries the frozen message field numbers; this module owns the v1
*semantics*: the public method registry with request/response message
classes, the ``4-byte unsigned big-endian length`` frame codec with the
16 MiB cap, and the fixed transport limits (Hello within 5 s of accept,
30 s between frame header and body, 5 min idle close, server default
request deadline 30 s, single Task.Wait at most 60 s, 64 connections,
32 in-flight requests per connection).
"""

from __future__ import annotations

import struct
from typing import Any

from ..domain.errors import ErrorCode, StableError
from ._v1 import public_pb2 as pub
from ._v1 import transport_pb2 as transport

__all__ = [
    "DEFAULT_REQUEST_DEADLINE_US",
    "HELLO_TIMEOUT_S",
    "IDLE_TIMEOUT_S",
    "MAX_CONNECTIONS",
    "MAX_FRAME_BYTES",
    "MAX_INFLIGHT_PER_CONNECTION",
    "MAX_WAIT_US",
    "METHODS",
    "PUBLIC_API_MAJOR",
    "PUBLIC_API_MINOR",
    "decode_frame_length",
    "encode_frame",
    "parse_envelope",
]

PUBLIC_API_MAJOR = 1
PUBLIC_API_MINOR = 15

MAX_FRAME_BYTES = 16 * 1024 * 1024
HELLO_TIMEOUT_S = 5.0
FRAME_GAP_S = 30.0
IDLE_TIMEOUT_S = 300.0
DEFAULT_REQUEST_DEADLINE_US = 30_000_000
MAX_WAIT_US = 60_000_000
MAX_CONNECTIONS = 64
MAX_INFLIGHT_PER_CONNECTION = 32

_PREFIX = "agent_meta.public.v1."


def _m(group: str, name: str, request: Any, response: Any) -> tuple[str, Any, Any]:
    return (_PREFIX + group + "." + name, request, response)


#: Public method registry → (request message class, response message class).
#: Mutations carry a ``CommandRequest`` wrapping the canonical
#: CommandEnvelope JCS and answer ``MutationResponse`` (§41.52).
METHODS: dict[str, tuple[Any, Any]] = {
    method: (request, response)
    for method, request, response in (
        _m("Runtime", "GetInfo", pub.GetInfoRequest, pub.RuntimeInfo),
        _m("Runtime", "GetView", pub.GetViewRequest, pub.ResourceResponse),
        _m("Runtime", "Doctor", pub.DoctorRequest, pub.DoctorResponse),
        _m("Runtime", "GetMetrics", pub.GetMetricsRequest, pub.GetMetricsResponse),
        _m("Runtime", "Stop", pub.CommandRequest, pub.MutationResponse),
        _m("Authority", "CreatePrincipal", pub.CommandRequest, pub.MutationResponse),
        _m("Authority", "Delegate", pub.CommandRequest, pub.MutationResponse),
        _m("Authority", "Revoke", pub.CommandRequest, pub.MutationResponse),
        _m("Task", "Submit", pub.CommandRequest, pub.MutationResponse),
        _m("Task", "Get", pub.GetTaskRequest, pub.ResourceResponse),
        _m("Task", "GetExecution", pub.GetTaskRequest, pub.ResourceResponse),
        _m("Task", "GetTrace", pub.GetTaskRequest, pub.ResourceResponse),
        _m("Task", "Wait", pub.WaitTaskRequest, pub.TaskWaitResponse),
        _m("Task", "Cancel", pub.CommandRequest, pub.MutationResponse),
        _m("Artifact", "BeginPut", pub.BeginPutRequest, pub.BeginPutResponse),
        _m("Artifact", "PutChunk", pub.PutChunkRequest, pub.PutChunkResponse),
        _m("Artifact", "Put", pub.CommandRequest, pub.MutationResponse),
        _m("Artifact", "GetManifest", pub.GetArtifactRequest, pub.ArtifactManifestResponse),
        _m("Artifact", "GetContent", pub.GetArtifactRequest, pub.ResourceResponse),
        _m("Artifact", "Verify", pub.VerifyArtifactRequest, pub.VerifyArtifactResponse),
        _m("State", "Create", pub.CommandRequest, pub.MutationResponse),
        _m("State", "Get", pub.CommandRequest, pub.MutationResponse),
        _m("State", "Write", pub.CommandRequest, pub.MutationResponse),
        _m("Composition", "Validate", pub.ValidateCompositionRequest, pub.ValidateCompositionResponse),
        _m("Composition", "Commit", pub.CommandRequest, pub.MutationResponse),
        _m("Composition", "GetRefs", pub.GetRefsRequest, pub.GetRefsResponse),
        _m("Harness", "ValidatePackage", pub.ValidateHarnessPackageRequest, pub.ResourceResponse),
        _m("Harness", "Get", pub.GetHarnessRequest, pub.ResourceResponse),
        _m("Harness", "List", pub.ListHarnessRequest, pub.ResourceResponse),
        _m("Harness", "Install", pub.CommandRequest, pub.MutationResponse),
        _m("Harness", "Activate", pub.CommandRequest, pub.MutationResponse),
        _m("Harness", "ConfigureProvider", pub.CommandRequest, pub.MutationResponse),
        _m("Harness", "ValidateProviderConfiguration", pub.CommandRequest, pub.ResourceResponse),
        _m("Harness", "Deactivate", pub.CommandRequest, pub.MutationResponse),
        _m("Harness", "Uninstall", pub.CommandRequest, pub.MutationResponse),
        _m("Evolution", "Propose", pub.CommandRequest, pub.MutationResponse),
        _m("Evolution", "RunExperiment", pub.CommandRequest, pub.MutationResponse),
        _m("Evolution", "GetExperiment", pub.GetExperimentRequest, pub.ResourceResponse),
        _m("Evolution", "WaitExperiment", pub.WaitExperimentRequest, pub.TaskWaitResponse),
        _m("Evolution", "Promote", pub.CommandRequest, pub.MutationResponse),
        _m("Evolution", "Rollback", pub.CommandRequest, pub.MutationResponse),
        _m("Graph", "Why", pub.WhyRequest, pub.WhyResponse),
        _m("Graph", "Lineage", pub.LineageRequest, pub.LineageResponse),
        _m("Operations", "GetOperation", pub.GetOperationRequest, pub.ResourceResponse),
        _m("Operations", "WaitOperation", pub.WaitOperationRequest, pub.ResourceResponse),
        _m("Operations", "Backup", pub.CommandRequest, pub.MutationResponse),
        _m("Operations", "GcPlan", pub.CommandRequest, pub.MutationResponse),
        _m("Operations", "GcApply", pub.CommandRequest, pub.MutationResponse),
    )
}

METHOD_MINORS = {"agent_meta.public.v1.Runtime.Stop": 1, "agent_meta.public.v1.Task.GetExecution": 2,
    'agent_meta.public.v1.State.Create':12,'agent_meta.public.v1.State.Get':12,'agent_meta.public.v1.State.Write':12,
    "agent_meta.public.v1.Artifact.GetContent": 3,
    "agent_meta.public.v1.Authority.CreatePrincipal": 4, "agent_meta.public.v1.Authority.Delegate": 4,
    "agent_meta.public.v1.Authority.Revoke": 4, "agent_meta.public.v1.Task.GetTrace": 5}


def encode_frame(payload: bytes) -> bytes:
    """Prefix ``payload`` with its 4-byte big-endian unsigned length."""

    if len(payload) > MAX_FRAME_BYTES:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="frame exceeds the 16 MiB limit",
            details={"size": len(payload), "max": MAX_FRAME_BYTES},
        )
    return struct.pack(">I", len(payload)) + payload


def decode_frame_length(header: bytes) -> int:
    """Validate a 4-byte frame header and return the body length.

    The length is validated *before* any buffer allocation (§41.26);
    oversized or short headers raise ``INVALID_ARGUMENT``.
    """

    if len(header) != 4:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="truncated frame header"
        )
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_BYTES:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="frame exceeds the 16 MiB limit",
            details={"size": length, "max": MAX_FRAME_BYTES},
        )
    return length


def parse_envelope(raw: bytes) -> transport.RpcEnvelope:
    envelope = transport.RpcEnvelope()
    try:
        envelope.ParseFromString(raw)
    except Exception as exc:  # malformed protobuf body: reject the frame
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT, message="malformed envelope"
        ) from exc
    return envelope
