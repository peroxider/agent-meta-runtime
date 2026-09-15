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
from pathlib import Path
from typing import Any

from ...domain.errors import ErrorCode, StableError
from ...protocols._v1 import transport_pb2 as t
from ...protocols.backend_wire import error_from_rpc, negotiate_version, new_request_id
from ...protocols.public_wire import (
    DEFAULT_REQUEST_DEADLINE_US,
    FRAME_GAP_S,
    HELLO_TIMEOUT_S,
    MAX_FRAME_BYTES,
    PUBLIC_API_MAJOR,
    PUBLIC_API_MINOR,
    decode_frame_length,
    encode_frame,
    parse_envelope,
)

__all__ = ["LocalConnection"]


class LocalConnection:
    """One sequential-request client connection to the local API."""

    def __init__(self, socket_path: Path) -> None:
        self._path = Path(socket_path)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._negotiated = (0, 0)

    # -- lifecycle -----------------------------------------------------------
    async def connect(self) -> tuple[int, int]:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._path), limit=MAX_FRAME_BYTES),
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
        response = await self.call(
            "Hello", hello, t.HelloResponse, deadline_us=int(HELLO_TIMEOUT_S * 1_000_000)
        )
        self._negotiated = (response.selected_major, response.selected_minor)
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

    @property
    def negotiated_version(self) -> tuple[int, int]:
        return self._negotiated

    # -- requests ------------------------------------------------------------
    async def call_raw(
        self, method: str, request_bytes: bytes, *, deadline_us: int | None = None
    ) -> bytes:
        """Send one raw request payload; return the raw response payload.

        The framing/error layer is identical to :meth:`call`; callers that
        already hold serialized messages (e.g. the SDK transport adapter)
        use this entry point.
        """

        if self._writer is None:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="not connected")
        deadline = deadline_us if deadline_us is not None else DEFAULT_REQUEST_DEADLINE_US
        envelope = t.RpcEnvelope(
            protocol_major=PUBLIC_API_MAJOR,
            protocol_minor=PUBLIC_API_MINOR,
            request_id=new_request_id(),
            method=method,
            deadline_at_us=deadline,
        )
        envelope.payload = request_bytes
        try:
            self._writer.write(encode_frame(envelope.SerializeToString()))
            await asyncio.wait_for(self._writer.drain(), FRAME_GAP_S)
            raw = await asyncio.wait_for(self._read_response(), FRAME_GAP_S)
        except (ConnectionError, OSError) as exc:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION, message="local connection lost"
            ) from exc
        response = parse_envelope(raw)
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
