"""Client side of the local RPC channel (§41.26).

Opens a UDS connection to ``<data_dir>/run/agent-meta.sock``, performs the
Hello handshake (version negotiation; major mismatch refuses), and then
exposes :meth:`LocalConnection.call` — send one length-framed
``RpcEnvelope`` request, await the matching framed response. Deadline and
limits mirror the server: 16 MiB frames, 30 s between frames, request-level
deadline from the envelope (default 30 s). Server errors are raised as
:class:`~agent_meta_runtime.domain.errors.StableError` so callers handle
one error surface.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
import time
from typing import Any

from ..domain.errors import ErrorCode, StableError
from ..protocols._v1 import transport_pb2 as t
from ..protocols.backend_wire import error_from_rpc, new_request_id
from ..protocols.public_wire import (
    DEFAULT_REQUEST_DEADLINE_US,
    FRAME_GAP_S,
    HELLO_TIMEOUT_S,
    MAX_FRAME_BYTES,
    PUBLIC_API_MAJOR,
    PUBLIC_API_MINOR,
    METHOD_MINORS,
    decode_frame_length,
    encode_frame,
    parse_envelope,
)

__all__ = ["LocalConnection", "LocalTransport", "connect", "open_local_streams", "pipe_name_for_data_dir"]


def pipe_name_for_data_dir(data_dir: Path) -> str:
    canonical = os.path.normcase(str(Path(data_dir).resolve()))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"\\\\.\\pipe\\agent-meta-{digest[:16]}"


async def open_local_streams(endpoint: Path | str):
    """Open UDS or a Windows Named Pipe; never falls back to TCP."""
    if os.name != "nt":
        return await asyncio.open_unix_connection(str(endpoint), limit=MAX_FRAME_BYTES)
    address = str(endpoint)
    if not address.startswith("\\\\.\\pipe\\"):
        address = pipe_name_for_data_dir(Path(endpoint).parent.parent)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_FRAME_BYTES)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.create_pipe_connection(lambda: protocol, address)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    try:
        from ._windows_peer import require_same_pipe_user

        require_same_pipe_user(writer.get_extra_info("pipe"), server_side=False)
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise
    return reader, writer


class LocalConnection:
    """One sequential-request client connection to the local API."""

    def __init__(self, socket_path: Path) -> None:
        self._path = Path(socket_path)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._negotiated = (0, 0)
        self._server_instance_id = None
        self._request_lock = asyncio.Lock()

    # -- lifecycle -----------------------------------------------------------
    async def connect(self) -> tuple[int, int]:
        if self._writer is not None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="already connected")
        try:
            self._reader, self._writer = await asyncio.wait_for(
                open_local_streams(self._path),
                HELLO_TIMEOUT_S,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="local endpoint unreachable"
            ) from exc
        hello = t.HelloRequest(
            supported=[
                t.VersionRange(
                    major=PUBLIC_API_MAJOR,
                    min_minor=0,
                    max_minor=PUBLIC_API_MINOR,
                )
            ]
        )
        try:
            response = await self.call(
                "Hello", hello, t.HelloResponse,
                deadline_us=time.time_ns() // 1000 + int(HELLO_TIMEOUT_S * 1_000_000),
            )
            if response.selected_major != PUBLIC_API_MAJOR or response.selected_minor > PUBLIC_API_MINOR:
                raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="invalid negotiated local API version")
            if not response.server_instance_id or len(response.server_instance_id) > 128:
                raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="local daemon instance identity missing or invalid")
        except BaseException:
            await self.close()
            raise
        self._negotiated = (response.selected_major, response.selected_minor)
        self._server_instance_id = response.server_instance_id
        return self._negotiated

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except ConnectionError:
                pass
        self._reader = None
        self._writer = None
        self._server_instance_id = None

    @property
    def negotiated_version(self) -> tuple[int, int]:
        return self._negotiated

    @property
    def server_instance_id(self) -> str | None:
        return self._server_instance_id

    # -- requests ------------------------------------------------------------
    async def call_raw(
        self, method: str, request_bytes: bytes, *, deadline_us: int | None = None
    ) -> bytes:
        """Send one raw request payload; return the raw response payload.

        The framing/error layer is identical to :meth:`call`; callers that
        already hold serialized messages (e.g. the SDK transport adapter)
        use this entry point.
        """

        async with self._request_lock:
            return await self._call_raw(method, request_bytes, deadline_us=deadline_us)

    async def _call_raw(self, method: str, request_bytes: bytes, *, deadline_us: int | None) -> bytes:
        if self._writer is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="not connected")
        if METHOD_MINORS.get(method, 0) > self._negotiated[1]:
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="method requires a newer negotiated API minor")
        deadline = deadline_us if deadline_us is not None else time.time_ns() // 1000 + DEFAULT_REQUEST_DEADLINE_US
        version = (PUBLIC_API_MAJOR, PUBLIC_API_MINOR) if method == "Hello" else self._negotiated
        envelope = t.RpcEnvelope(
            protocol_major=version[0],
            protocol_minor=version[1],
            request_id=new_request_id(),
            method=method,
            deadline_at_us=deadline,
        )
        envelope.payload = request_bytes
        try:
            self._writer.write(encode_frame(envelope.SerializeToString()))
            await asyncio.wait_for(self._writer.drain(), FRAME_GAP_S)
            remaining = max(0, (deadline - time.time_ns() // 1000) / 1_000_000)
            raw = await asyncio.wait_for(self._read_response(), remaining)
        except asyncio.TimeoutError as exc:
            # An unread late response must never be mistaken for the next call.
            await self.close()
            raise StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="local request deadline") from exc
        except asyncio.CancelledError:
            await self.close()
            raise
        except (ConnectionError, OSError, asyncio.IncompleteReadError) as exc:
            await self.close()
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="local connection lost"
            ) from exc
        try:
            response = parse_envelope(raw)
        except StableError:
            await self.close()
            raise
        if response.request_id != envelope.request_id or response.method != method or response.protocol_major != PUBLIC_API_MAJOR or not response.is_response:
            await self.close()
            raise StableError(code=ErrorCode.INTERNAL, message="response does not match local request")
        if response.error and response.error.code:
            raise error_from_rpc(response.error)
        if not response.is_response or not response.HasField("payload"):
            raise StableError(code=ErrorCode.INTERNAL, message="malformed response frame")
        return bytes(response.payload)

    async def call(
        self,
        method: str,
        request: Any,
        response_type: type,
        *,
        deadline_us: int | None = None,
    ) -> Any:
        """Send one request and return the parsed response message.

        Raises :class:`StableError` mapped from the wire error on failure.
        """

        if self._writer is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="not connected")
        raw_payload = await self.call_raw(
            method, request.SerializeToString(), deadline_us=deadline_us
        )
        result = response_type()
        result.ParseFromString(raw_payload)
        return result

    async def _read_response(self) -> bytes:
        assert self._reader is not None
        header = await self._reader.readexactly(4)
        length = decode_frame_length(header)
        return await self._reader.readexactly(length)


class LocalTransport:
    """Public Transport implementation carrying serialized local RPC messages."""

    def __init__(self, connection: LocalConnection) -> None:
        self._connection = connection

    @property
    def server_instance_id(self) -> str | None:
        return self._connection.server_instance_id

    @property
    def negotiated_version(self) -> tuple[int, int]:
        return self._connection.negotiated_version

    async def call(self, method: str, request: bytes, *, deadline_us: int | None = None) -> bytes:
        return await self._connection.call_raw(method, request, deadline_us=deadline_us)

    async def close(self) -> None:
        await self._connection.close()


async def connect(data_dir: Path | str, *, authority=None):
    """Connect to an already running local Runtime and return its public client."""
    from .client import AgentMetaClient

    connection = LocalConnection(Path(data_dir) / "run" / "agent-meta.sock")
    await connection.connect()
    return AgentMetaClient(LocalTransport(connection), authority=authority)
