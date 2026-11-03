"""Public SDK exports (§41.52): typed DTOs only — no private wire or
storage types leak through this namespace."""

from .client import (
    AgentMetaClient,
    MutationResult,
    RuntimeInfo,
    StagingSession,
    TaskHandle,
    Transport,
)
from .transport import LocalTransport, connect
from .commands import CommandAuthority, decode_command, encode_command, sign_command
from ..domain.errors import ErrorCode, StableError

__all__ = [
    "AgentMetaClient",
    "MutationResult",
    "RuntimeInfo",
    "StagingSession",
    "TaskHandle",
    "Transport",
    "LocalTransport",
    "connect",
    "ErrorCode",
    "StableError",
    "CommandAuthority",
    "decode_command",
    "encode_command",
    "sign_command",
]
