"""Private bounded control frames; never persist them as Artifacts or Facts."""
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct

from ..domain.canonical import canonical_json
from ..domain.execution_tokens import ExecutionTokenBinding, ExecutionTokenVerifier
from ..domain.provider_transport import ProviderEgressPolicy, ProviderHttpOutcome, ProviderHttpRequest
from .crypto import verify_signature

MAX_FRAME_BYTES = 3 << 20
_BINDING_FIELDS = {"backend_session_id", "realm_id", "epoch_id", "actor_id", "action_id", "effect_kind",
    "target_scope_hash", "resource_ceiling", "required_permissions", "deadline_at_us"}


def _hex(value, maximum):
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise ValueError("invalid worker byte encoding")
    return bytes.fromhex(value)


def document(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise ValueError("invalid worker frame size")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError("worker frame must be canonical JSON")
    return value


def _read_exact(stream, size):
    chunks = []
    while size:
        value = stream.read(size)
        if not value:
            raise EOFError("incomplete worker frame")
        chunks.append(value)
        size -= len(value)
    return b"".join(chunks)


def read_frame(stream):
    size, = struct.unpack(">I", _read_exact(stream, 4))
    if not 0 < size <= MAX_FRAME_BYTES:
        raise ValueError("worker frame exceeds ceiling")
    return _read_exact(stream, size)


def write_frame(stream, value):
    raw = canonical_json(value)
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise ValueError("worker frame exceeds ceiling")
    stream.write(struct.pack(">I", len(raw)) + raw)
    stream.flush()


@dataclass(frozen=True, slots=True)
class ProviderWorkerBootstrap:
    root_principal_id: str
    root_public_key: bytes
    realm_id: str
    epoch_id: str
    certificate: bytes
    session_id: str
    credential_root: str
    credential_profile: str
    trusted_ca_pem: bytes | None = None

    def __post_init__(self):
        if not isinstance(self.credential_root, str) or len(self.credential_root) > 4096 or not Path(self.credential_root).is_absolute():
            raise ValueError("worker credential root must be an absolute enforcement path")
        if self.credential_profile not in ("WINDOWS_DPAPI_CURRENT_USER", "INSECURE_TEST_ONLY"):
            raise ValueError("worker credential profile unavailable")
        if not isinstance(self.session_id, str) or not 1 <= len(self.session_id) <= 256:
            raise ValueError("invalid worker session")
        if type(self.root_public_key) is not bytes or len(self.root_public_key) != 32 or type(self.certificate) is not bytes or len(self.certificate) > 16384:
            raise ValueError("invalid worker trust bytes")
        if self.trusted_ca_pem is not None and (type(self.trusted_ca_pem) is not bytes or not 0 < len(self.trusted_ca_pem) <= 65536):
            raise ValueError("invalid worker TLS anchor")

    def verifier(self):
        return ExecutionTokenVerifier(root_principal_id=self.root_principal_id, root_public_key=self.root_public_key,
            realm_id=self.realm_id, epoch_id=self.epoch_id, certificate=self.certificate, verify_signature=verify_signature)

    def to_json(self):
        return {"root_principal_id": self.root_principal_id, "root_public_key": self.root_public_key.hex(),
            "realm_id": self.realm_id, "epoch_id": self.epoch_id, "certificate": self.certificate.hex(),
            "session_id": self.session_id, "credential_root": self.credential_root,
            "credential_profile": self.credential_profile,
            "trusted_ca_pem": self.trusted_ca_pem.hex() if self.trusted_ca_pem is not None else None}


def command(bootstrap, request, *, authorization, binding):
    return {"schema": "provider-worker-command/v1", "bootstrap": bootstrap.to_json(),
        "request": {**request.to_json(), "body_hex": request.body.hex()}, "authorization": authorization.hex(),
        "binding": {name: getattr(binding, name) for name in _BINDING_FIELDS - {"resource_ceiling", "required_permissions"}} |
            {"resource_ceiling": dict(binding.resource_ceiling), "required_permissions": sorted(binding.required_permissions)}}


def parse_command(raw):
    value = document(raw)
    if set(value) != {"schema", "bootstrap", "request", "authorization", "binding"} or value["schema"] != "provider-worker-command/v1":
        raise ValueError("invalid worker command")
    boot = value["bootstrap"]
    if not isinstance(boot, dict) or set(boot) != set(ProviderWorkerBootstrap.__dataclass_fields__):
        raise ValueError("invalid worker bootstrap")
    bootstrap = ProviderWorkerBootstrap(**{**boot, "root_public_key": _hex(boot["root_public_key"], 32),
        "certificate": _hex(boot["certificate"], 16384),
        "trusted_ca_pem": _hex(boot["trusted_ca_pem"], 65536) if boot["trusted_ca_pem"] is not None else None})
    body, policy = value["request"], value["request"].get("policy") if isinstance(value["request"], dict) else None
    if not isinstance(body, dict) or set(body) != {"schema", "request_id", "policy", "model", "credential_handle", "body_sha256", "body_hex", "timeout_us", "maximum_response_bytes", "deadline_at_us"} or body["schema"] != "controlled-provider-http/v1":
        raise ValueError("invalid worker request")
    if not isinstance(policy, dict) or set(policy) != {"schema", "scheme", "host", "port", "path", "networks", "profile"} or policy["schema"] != "provider-egress/v1" or policy["scheme"] != "https":
        raise ValueError("invalid worker policy")
    request = ProviderHttpRequest(body["request_id"], ProviderEgressPolicy(**{k:policy[k] for k in
        ("host", "port", "path", "networks", "profile")}), body["model"], body["credential_handle"],
        _hex(body["body_hex"], 1 << 20), body["timeout_us"], body["maximum_response_bytes"], body["deadline_at_us"])
    if request.to_json() != {k:v for k,v in body.items() if k != "body_hex"}:
        raise ValueError("worker request identity differs")
    binding = value["binding"]
    if not isinstance(binding, dict) or set(binding) != _BINDING_FIELDS or not isinstance(binding["required_permissions"], list) or binding["required_permissions"] != sorted(set(binding["required_permissions"])):
        raise ValueError("invalid worker execution binding")
    binding = ExecutionTokenBinding(**{**binding, "required_permissions": frozenset(binding["required_permissions"])})
    if (binding.backend_session_id, binding.realm_id, binding.epoch_id) != (bootstrap.session_id, bootstrap.realm_id, bootstrap.epoch_id):
        raise ValueError("worker session/trust binding differs")
    return bootstrap, request, _hex(value["authorization"], 16384), binding


def outcome_document(outcome, *, request_id=None, scope_hash=None):
    return {"schema": "provider-worker-outcome/v1", "state": outcome.state,
        "request_id": request_id, "request_scope_hash": scope_hash,
        "content_hex": outcome.content.hex() if outcome.content is not None else None,
        "error_code": outcome.error_code, "reason_code": outcome.reason_code,
        "http_status": outcome.http_status, "retry_after_us": outcome.retry_after_us}


def parse_outcome(raw, *, expected_request_id=None, expected_scope_hash=None):
    value = document(raw)
    if set(value) != {"schema", "state", "request_id", "request_scope_hash", "content_hex", "error_code", "reason_code", "http_status", "retry_after_us"} or value["schema"] != "provider-worker-outcome/v1":
        raise ValueError("invalid worker outcome")
    if expected_request_id is not None and value["request_id"] != expected_request_id:
        raise ValueError("worker result request binding differs")
    if expected_scope_hash is not None and value["request_scope_hash"] != expected_scope_hash:
        raise ValueError("worker result scope binding differs")
    if value["http_status"] is not None and (type(value["http_status"]) is not int or not 100 <= value["http_status"] <= 599):
        raise ValueError("invalid HTTP status")
    if value["retry_after_us"] is not None and (type(value["retry_after_us"]) is not int or not 0 <= value["retry_after_us"] <= 3_600_000_000):
        raise ValueError("invalid retry metadata")
    if value["reason_code"] is not None and (not isinstance(value["reason_code"], str) or re.fullmatch(r"[A-Z_]{1,80}", value["reason_code"]) is None):
        raise ValueError("invalid worker diagnostic")
    return ProviderHttpOutcome(value["state"], _hex(value["content_hex"], 1 << 20) if value["content_hex"] is not None else None,
        value["error_code"], value["reason_code"], value["http_status"], value["retry_after_us"])
