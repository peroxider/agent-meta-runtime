"""Frozen inputs/outcomes for the controlled Provider HTTPS edge.

These internal DTOs carry public handles and bounded bytes, never credentials.
They do not replace admission, pricing or durable Invocation accounting.
"""
from dataclasses import dataclass
import ipaddress
import json
import re

from .canonical import canonical_json, sha256_hex
from .errors import ErrorCode, StableError
from .execution_tokens import ExecutionTokenBinding

_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/[A-Za-z0-9_./~-]*\Z")
_MODEL = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
MAX_PROVIDER_BYTES = 1 << 20


def _invalid(reason):
    return StableError(code=ErrorCode.INVALID_ARGUMENT, message="invalid controlled Provider request",
        details={"reason_code": reason})


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class ProviderEgressPolicy:
    host: str
    port: int
    path: str
    networks: tuple[str, ...] = ("0.0.0.0/0", "::/0")
    profile: str = "PUBLIC_HTTPS"

    def __post_init__(self):
        if not isinstance(self.host, str) or len(self.host) > 253 or not all(_HOST.fullmatch(x) for x in self.host.split(".")):
            raise _invalid("HOST")
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            pass
        else:
            raise _invalid("DNS_HOST_REQUIRED")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise _invalid("PORT")
        if not isinstance(self.path, str) or len(self.path) > 1024 or not _PATH.fullmatch(self.path) or self.path.startswith("//") or any(x in (".", "..") for x in self.path.split("/")):
            raise _invalid("PATH")
        if self.profile not in ("PUBLIC_HTTPS", "CONTROLLED_TEST_ONLY"):
            raise _invalid("PROFILE")
        try:
            nets = tuple(self.networks)
            if not 1 <= len(nets) <= 32 or not all(isinstance(x, str) for x in nets):
                raise ValueError("network set")
            if nets != tuple(sorted(set(str(ipaddress.ip_network(x, strict=True)) for x in nets))):
                raise ValueError("network encoding")
        except (ValueError, TypeError):
            raise _invalid("NETWORKS") from None
        object.__setattr__(self, "networks", nets)

    def to_json(self):
        return {"schema": "provider-egress/v1", "scheme": "https", "host": self.host,
            "port": self.port, "path": self.path, "networks": list(self.networks), "profile": self.profile}

    def permits_ip(self, value):
        try:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and (address.ipv4_mapped or address.sixtofour or address.teredo or address.scope_id):
                return False
            if address.is_multicast or address.is_unspecified or (address.is_reserved and not
                    (self.profile == "CONTROLLED_TEST_ONLY" and address.is_loopback)):
                return False
            if self.profile == "PUBLIC_HTTPS" and (not address.is_global or address.is_loopback or address.is_link_local or address.is_private):
                return False
            return any(address.version == network.version and address in network for network in map(ipaddress.ip_network, self.networks))
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class ProviderHttpRequest:
    request_id: str
    policy: ProviderEgressPolicy
    model: str
    credential_handle: str
    body: bytes
    timeout_us: int
    maximum_response_bytes: int = MAX_PROVIDER_BYTES
    deadline_at_us: int | None = None

    def __post_init__(self):
        if not isinstance(self.request_id, str) or not 1 <= len(self.request_id) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in self.request_id):
            raise _invalid("REQUEST_ID")
        if not isinstance(self.policy, ProviderEgressPolicy) or not isinstance(self.model, str) or not _MODEL.fullmatch(self.model):
            raise _invalid("MODEL_POLICY")
        if not isinstance(self.credential_handle, str) or not self.credential_handle.startswith("credential://") or len(self.credential_handle) > 256 or not re.fullmatch(r"[A-Za-z0-9:/._-]+", self.credential_handle):
            raise _invalid("CREDENTIAL_HANDLE")
        if type(self.timeout_us) is not int or not 0 < self.timeout_us <= 300_000_000:
            raise _invalid("TIMEOUT")
        if type(self.maximum_response_bytes) is not int or not 0 < self.maximum_response_bytes <= MAX_PROVIDER_BYTES:
            raise _invalid("RESPONSE_CEILING")
        if self.deadline_at_us is not None and (type(self.deadline_at_us) is not int or not 0 <= self.deadline_at_us <= 2**53 - 1):
            raise _invalid("DEADLINE")
        if type(self.body) is not bytes or not 0 < len(self.body) <= MAX_PROVIDER_BYTES:
            raise _invalid("BODY_SIZE")
        try:
            body = json.loads(self.body.decode("utf-8"), object_pairs_hook=_pairs)
            if not isinstance(body, dict) or canonical_json(body) != self.body:
                raise ValueError("canonical body required")
            if not {"model", "messages", "max_tokens", "stream"} <= set(body) or set(body) - {
                    "model", "messages", "max_tokens", "stream", "system", "tools", "tool_choice", "temperature", "top_p", "stop_sequences"}:
                raise ValueError("request fields")
            if body["model"] != self.model or body["stream"] is not False or type(body["max_tokens"]) is not int or not 0 < body["max_tokens"] <= 2**31 - 1:
                raise ValueError("request model/ceiling")
            if not isinstance(body["messages"], list) or not 1 <= len(body["messages"]) <= 256:
                raise ValueError("request history")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise _invalid("BODY_BINDING") from None

    def to_json(self):
        return {"schema": "controlled-provider-http/v1", "request_id": self.request_id,
            "policy": self.policy.to_json(), "model": self.model, "credential_handle": self.credential_handle,
            "body_sha256": sha256_hex(self.body), "timeout_us": self.timeout_us,
            "maximum_response_bytes": self.maximum_response_bytes, "deadline_at_us": self.deadline_at_us}

    @property
    def scope_hash(self):
        return sha256_hex(canonical_json(self.to_json()))

    @property
    def required_ceiling(self):
        return {"model_calls": 1, "request_bytes": len(self.body), "response_bytes": self.maximum_response_bytes,
            "output_tokens": json.loads(self.body)["max_tokens"], "wall_time_us": self.timeout_us}


@dataclass(frozen=True, slots=True)
class ProviderHttpOutcome:
    state: str
    content: bytes | None = None
    error_code: str | None = None
    reason_code: str | None = None
    http_status: int | None = None
    retry_after_us: int | None = None

    def __post_init__(self):
        if self.state not in ("NOT_SENT", "RESPONSE", "UNKNOWN") or (self.content is None) == (self.error_code is None):
            raise ValueError("exactly one bounded Provider outcome required")
        if self.content is not None and (self.state != "RESPONSE" or type(self.content) is not bytes or len(self.content) > MAX_PROVIDER_BYTES):
            raise ValueError("invalid Provider response bytes")
        if self.error_code is not None and self.error_code not in ErrorCode.ALL:
            raise ValueError("invalid Provider error")
        if self.state == "UNKNOWN" and self.error_code != ErrorCode.EXTERNAL_EFFECT_UNKNOWN:
            raise ValueError("unknown Provider effect requires the stable unknown code")


def authorize_provider_request(verifier, request, *, authorization, binding, now_us):
    """Independently bind concrete request needs before any native effect."""
    def deny(reason):
        return StableError(code=ErrorCode.AUTHORITY_DENIED, message="controlled Provider authorization rejected",
            details={"reason_code": reason})
    if not isinstance(request, ProviderHttpRequest) or not isinstance(binding, ExecutionTokenBinding):
        raise deny("REQUEST_TYPE")
    if binding.effect_kind != "model.invoke" or "model.invoke" not in binding.required_permissions or binding.target_scope_hash != request.scope_hash or dict(binding.resource_ceiling) != request.required_ceiling:
        raise deny("REQUEST_BINDING")
    audit = verifier.verify(authorization, request_id=request.request_id,
        request_payload_hash=request.scope_hash, binding=binding, now_us=now_us)
    if json.loads(authorization)["payload"]["resource_ceiling"] != request.required_ceiling:
        raise deny("ATTENUATED_CEILING_INSUFFICIENT")
    fingerprint = sha256_hex(canonical_json({"request": request.scope_hash,
        "session": binding.backend_session_id, "realm": binding.realm_id, "epoch": binding.epoch_id,
        "actor": binding.actor_id, "action": binding.action_id, "effect": binding.effect_kind}))
    remaining = min(request.timeout_us, audit.expires_at_us - now_us)
    if request.deadline_at_us is not None:
        remaining = min(remaining, request.deadline_at_us - now_us)
    return audit, remaining, fingerprint
