"""Normalized Host activity data and its execution edge; no native handles."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from ..domain.provider_accounting import ProviderReservation
from ..domain.provider_transport import ProviderHttpRequest


@dataclass(frozen=True, slots=True)
class HostCallValue:
    content: bytes | None = None
    error_code: str | None = None
    usage: Mapping | None = None
    backend_result: Mapping | None = None
    raise_error: bool = False

    def __post_init__(self):
        if (self.content is None) == (self.error_code is None):
            raise ValueError("Host activity has exactly one normalized outcome")
        if self.content is not None and not isinstance(self.content, bytes):
            raise ValueError("Host activity content must be immutable bytes")
        for field in ("usage", "backend_result"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, MappingProxyType(dict(value)))


class HostActivityRunner(Protocol):
    async def invoke(self, *, task, invocation_id, kind, capability_id, operation, content, execute) -> HostCallValue: ...


@dataclass(frozen=True, slots=True)
class PreparedProviderCall:
    """Runtime-only preparation; never returned through the public facade."""
    reservation: ProviderReservation
    request: ProviderHttpRequest
    normalize: Callable[[bytes], HostCallValue]

    def __post_init__(self):
        if (type(self.reservation) is not ProviderReservation or type(self.request) is not ProviderHttpRequest
                or not callable(self.normalize) or self.reservation.request_hash != self.request.scope_hash
                or self.reservation.maximum_output_tokens != self.request.required_ceiling["output_tokens"]):
            raise ValueError("Provider preparation differs from its reservation")


class ProviderModelHost(Protocol):
    """Root composition responsibility, never an external package plugin.

    Preparation independently checks the frozen operator-approved profile,
    binding, exact tokenizer/projection and firm maximum cost before admission.
    The implementation must derive billable usage from the controlled response
    and frozen pricing; a package normalizer's cost claim is not authority to
    release a reservation. Profiles/backend prerequisites unavailable => reject.
    """
    def prepare(self, *, task, ordinal, capability_id, operation, plan, projection, normalize) -> PreparedProviderCall: ...
    # Owns terminal commit; the generic Host activity runner must not recommit.
    async def invoke(self, *, task, invocation_id, prepared: PreparedProviderCall) -> HostCallValue: ...
