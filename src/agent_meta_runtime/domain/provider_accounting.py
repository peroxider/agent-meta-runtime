"""Internal, secretless admission evidence for one non-retryable Provider call.

The enforcing coordinator must verify the frozen profile, exact tokenizer and
pricing artifacts before constructing this value. This DTO does not perform
that verification and is deliberately absent from the public SDK.
"""

from dataclasses import asdict, dataclass
from collections.abc import Mapping
import re

from .errors import ErrorCode, StableError
from .ids import validate_id


def amount(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


@dataclass(frozen=True, slots=True)
class ProviderReservation:
    profile_artifact_id: str
    pricing_artifact_id: str
    tokenizer_artifact_id: str
    request_hash: str
    input_tokens: int
    maximum_output_tokens: int
    maximum_cost_microunits: int
    configuration_fact_id: str | None = None
    deadline_at_us: int | None = None

    def __post_init__(self):
        refs = (self.profile_artifact_id, self.pricing_artifact_id, self.tokenizer_artifact_id)
        if (any(not isinstance(ref, str) or not re.fullmatch(r"artifact://sha256/[0-9a-f]{64}", ref) for ref in refs)
                or not isinstance(self.request_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", self.request_hash)
                or any(not amount(value) for value in (self.input_tokens, self.maximum_output_tokens, self.maximum_cost_microunits))
                or self.maximum_output_tokens == 0):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid Provider reservation")
        if self.configuration_fact_id is not None or self.deadline_at_us is not None:
            try:
                validate_id(self.configuration_fact_id)
                if (not self.configuration_fact_id.startswith('fact://') or not amount(self.deadline_at_us)
                        or self.deadline_at_us == 0):
                    raise ValueError('invalid configured reservation')
            except (TypeError, ValueError, AttributeError):
                raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid configured Provider reservation") from None

    def document(self):
        value = asdict(self)
        if self.configuration_fact_id is None:
            value.pop('configuration_fact_id')
            value.pop('deadline_at_us')
            return {"schema": "provider-reservation/v1", **value}
        return {"schema": "provider-reservation/v2", **value}


def settlement(reservation, outcome, usage):
    """Keep a conservative liability even when a terminal has no known bill."""
    if outcome not in ("NOT_SENT", "CONFIRMED", "UNKNOWN"):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid Provider accounting outcome")
    if usage is not None and not isinstance(usage, Mapping):
        raise StableError(code=ErrorCode.INVALID_RESULT, message="invalid Provider usage shape")
    usage = dict(usage or {})
    if set(usage) - {"input_tokens", "output_tokens", "cost_microunits"} or any(
            value is not None and not amount(value) for value in usage.values()):
        raise StableError(code=ErrorCode.INVALID_RESULT, message="invalid Provider usage")
    usage = {key: usage.get(key) for key in ("input_tokens", "output_tokens", "cost_microunits")}
    if outcome == "NOT_SENT":
        if any(value not in (None, 0) for value in usage.values()):
            raise StableError(code=ErrorCode.INVALID_RESULT, message="unsent Provider request cannot have billable usage")
        usage = dict(input_tokens=None, output_tokens=None, cost_microunits=0)
    overrun = any(usage[key] is not None and usage[key] > reservation[limit] for key, limit in (
        ("input_tokens", "input_tokens"), ("output_tokens", "maximum_output_tokens"),
        ("cost_microunits", "maximum_cost_microunits")))
    cost = usage["cost_microunits"]
    liability = cost if outcome != "UNKNOWN" and cost is not None else max(reservation["maximum_cost_microunits"], cost or 0)
    return {"schema": "provider-settlement/v1", "outcome": outcome, "usage": usage,
        "liability_microunits": liability, "overrun": overrun}
