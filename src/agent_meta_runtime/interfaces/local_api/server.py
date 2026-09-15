"""Local RPC server (§41.26, §41.49.1): framed RpcEnvelope over UDS.

Per-connection state machine: peer UID is verified before any payload is
read; the first message must be a Hello (API major/minor negotiation,
major mismatch closes); every subsequent message is a 4-byte big-endian
length-framed ``RpcEnvelope`` request. Enforced limits: at most
``MAX_CONNECTIONS`` concurrent connections, ``MAX_INFLIGHT_PER_CONNECTION``
in-flight requests per connection with each request_id usable once per
connection, Hello within 5 s of accept, 30 s between frames, 5 min idle
close, and the fixed 16 MiB frame cap validated before allocation. Bad
frames error or close only their own connection — the daemon keeps serving.
Request handlers are ``async def handler(request_msg, deadline_at_us) ->
response_msg`` callables registered per method by the host.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

from ...domain.errors import ErrorCode, StableError
from ...protocols._v1 import transport_pb2 as transport
from ...protocols.backend_wire import error_to_rpc, negotiate_version
from ...protocols.public_wire import (
    DEFAULT_REQUEST_DEADLINE_US,
    FRAME_GAP_S,
    HELLO_TIMEOUT_S,
    IDLE_TIMEOUT_S,
    MAX_CONNECTIONS,
    MAX_FRAME_BYTES,
    MAX_INFLIGHT_PER_CONNECTION,
    METHODS,
    PUBLIC_API_MAJOR,
    PUBLIC_API_MINOR,
    decode_frame_length,
    encode_frame,
    parse_envelope,
)
from .peer import prepare_socket_dir, require_same_uid, socket_path_for_data_dir

__all__ = ["LocalApiServer"]

Handler = Callable[[Any, int], Awaitable[Any]]


class _ConnectionState:
    __slots__ = ("inflight",)

    def __init__(self) -> None:
        self.inflight: set[str] = set()


class LocalApiServer:
    """Async local API server bound to a UDS endpoint."""

    def __init__(
        self,
        data_dir: Path,
        *,
        handlers: dict[str, Handler],
        instance_id: str | None = None,
        now_us: Callable[[], int] | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._handlers = handlers
        self._instance_id = instance_id or uuid.uuid4().hex
        self._now_us = now_us or (lambda: 0)
        self._server: asyncio.Server | None = None
        self._connections: set[asyncio.StreamWriter] = set()

    # -- lifecycle -----------------------------------------------------------
    async def start(self) -> Path:
        run_dir = prepare_socket_dir(self._data_dir)
        path = socket_path_for_data_dir(self._data_dir)
        path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(
            self._handle_connection, path=str(path), limit=MAX_FRAME_BYTES
        )
        os.chmod(path, 0o600)
        os.chmod(run_dir, 0o700)
        return path

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for writer in list(self._connections):
            writer.close()
        self._connections.clear()
        socket_path_for_data_dir(self._data_dir).unlink(missing_ok=True)

    @property
    def instance_id(self) -> str:
        return self._instance_id

    # -- connection loop -------------------------------------------------------
    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if len(self._connections) >= MAX_CONNECTIONS:
            writer.close()
            return
        self._connections.add(writer)
        state = _ConnectionState()
        try:
            try:
                # Peer identity before any payload processing (§41.49.1).
                sock = writer.get_extra_info("socket")
                if sock is not None:
                    require_same_uid(sock, os.getuid())
                await asyncio.wait_for(self._handshake(reader, writer), HELLO_TIMEOUT_S)
                await self._request_loop(reader, writer, state)
            except (
                StableError,
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,  # clean client EOF
                ConnectionError,
                OSError,
            ):
                pass  # close only this connection
        finally:
            self._connections.discard(writer)
            writer.close()

    async def _handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        from ...protocols._v1 import transport_pb2 as t

        raw = await self._read_frame(reader)
        hello = parse_envelope(raw)
        if hello.method != "Hello":
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Hello required")
        request = t.HelloRequest()
        if hello.HasField("payload"):
            request.ParseFromString(bytes(hello.payload))
        major, minor = negotiate_version(
            request.supported, server_major=PUBLIC_API_MAJOR, server_minor=PUBLIC_API_MINOR
        )
        response = t.HelloResponse(
            selected_major=major,
            selected_minor=minor,
            server_instance_id=self._instance_id,
            server_time_us=self._now_us(),
            max_frame_bytes=MAX_FRAME_BYTES,
        )
        writer.write(
            encode_frame(build_response_envelope(hello, response.SerializeToString()))
        )
        await writer.drain()

    async def _request_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        state: _ConnectionState,
    ) -> None:
        while True:
            try:
                raw = await asyncio.wait_for(self._read_frame(reader), IDLE_TIMEOUT_S)
            except asyncio.TimeoutError:
                return  # idle close
            envelope = parse_envelope(raw)
            if envelope.is_response:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="server received a response envelope",
                )
            if envelope.request_id in state.inflight:
                error = error_to_rpc(
                    StableError(
                        code=ErrorCode.INVALID_ARGUMENT,
                        message="request id already in flight on this connection",
                    ),
                    correlation_id=envelope.request_id,
                )
                writer.write(
                    encode_frame(
                        error_envelope(envelope.method, envelope.request_id, error)
                    )
                )
                await writer.drain()
                continue
            if len(state.inflight) >= MAX_INFLIGHT_PER_CONNECTION:
                error = error_to_rpc(
                    StableError(
                        code=ErrorCode.RESOURCE_EXHAUSTED,
                        message="too many in-flight requests on this connection",
                    ),
                    correlation_id=envelope.request_id,
                )
                writer.write(
                    encode_frame(
                        error_envelope(envelope.method, envelope.request_id, error)
                    )
                )
                await writer.drain()
                continue
            # Serialized per connection for v0.1: each request is answered
            # before the next frame is read; the request_id bookkeeping still
            # enforces the one-use-per-connection rule (§41.26).
            state.inflight.add(envelope.request_id)
            try:
                response = await self._dispatch(envelope)
            finally:
                state.inflight.discard(envelope.request_id)
            writer.write(encode_frame(response))
            await writer.drain()

    async def _dispatch(self, envelope: transport.RpcEnvelope) -> bytes:
        request_id = envelope.request_id or uuid.uuid4().hex
        try:
            if envelope.method not in METHODS:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message=f"unknown method: {envelope.method}",
                )
            if not envelope.HasField("payload"):
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="request envelope carries no payload",
                )
            request_cls, response_cls = METHODS[envelope.method]
            request = request_cls()
            try:
                request.ParseFromString(bytes(envelope.payload))
            except Exception as exc:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT, message="malformed request payload"
                ) from exc
            deadline = envelope.deadline_at_us or self._now_us() + DEFAULT_REQUEST_DEADLINE_US
            handler = self._handlers[envelope.method]
            result = await asyncio.wait_for(
                handler(request, deadline),
                timeout=max((deadline - self._now_us()) / 1e6, 0.001),
            )
            if not isinstance(result, response_cls):
                raise StableError(
                    code=ErrorCode.INTERNAL, message="handler returned wrong type"
                )
            return build_response_envelope(envelope, result.SerializeToString())
        except StableError as exc:
            return error_envelope(
                envelope.method, request_id, error_to_rpc(exc, correlation_id=request_id)
            )
        except asyncio.TimeoutError:
            return error_envelope(
                envelope.method,
                request_id,
                error_to_rpc(
                    StableError(code=ErrorCode.DEADLINE_EXCEEDED, message="request deadline"),
                    correlation_id=request_id,
                ),
            )
        except Exception:
            return error_envelope(
                envelope.method,
                request_id,
                error_to_rpc(
                    StableError(code=ErrorCode.INTERNAL, message="internal error"),
                    correlation_id=request_id,
                ),
            )

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> bytes:
        header = await reader.readexactly(4)
        length = decode_frame_length(header)
        return await asyncio.wait_for(reader.readexactly(length), FRAME_GAP_S)


def build_response_envelope(
    request: transport.RpcEnvelope, payload: bytes
) -> bytes:
    response = transport.RpcEnvelope(
        protocol_major=request.protocol_major,
        protocol_minor=request.protocol_minor,
        request_id=request.request_id,
        method=request.method,
        is_response=True,
    )
    response.payload = payload
    return response.SerializeToString()


def error_envelope(method: str, request_id: str, error: transport.RpcError) -> bytes:
    response = transport.RpcEnvelope(
        protocol_major=PUBLIC_API_MAJOR,
        request_id=request_id,
        method=method,
        is_response=True,
    )
    response.error.CopyFrom(error)
    return response.SerializeToString()
