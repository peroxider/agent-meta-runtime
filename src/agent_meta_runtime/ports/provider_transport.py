"""Runtime-only controlled transport port; no Provider native object to Loop."""
import asyncio
from typing import Protocol
from ..domain.execution_tokens import ExecutionTokenBinding
from ..domain.provider_transport import ProviderHttpOutcome, ProviderHttpRequest


class ControlledProviderTransport(Protocol):
    def post(self, request: ProviderHttpRequest, *, authorization: bytes,
             binding: ExecutionTokenBinding, now_us: int) -> ProviderHttpOutcome: ...


class ProviderWorkerInterrupted(asyncio.CancelledError):
    """The admitted caller must journal outcome before cancelling its Task."""
    def __init__(self, outcome: ProviderHttpOutcome):
        super().__init__("controlled Provider worker interrupted")
        self.outcome = outcome


class ControlledProviderWorker(Protocol):
    @property
    def session_id(self) -> str: ...
    async def run(self, request: ProviderHttpRequest, *, authorization: bytes,
                  binding: ExecutionTokenBinding) -> ProviderHttpOutcome: ...
    async def close(self) -> None: ...
