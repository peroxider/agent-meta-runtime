"""Strict JCS/Ed25519 execution authorization (§41.41); no secret storage.

Crypto and signing are injected. Root trust is configured independently of the
certificate, and the enforcement caller derives the expected binding from its
registered operation, not from the token's claims.
"""

from dataclasses import dataclass
import json
import threading
from types import MappingProxyType
from typing import Callable, Mapping

from .authority import PERMISSIONS
from .canonical import canonical_json, sha256_hex
from .compatibility import EFFECT_REGISTRY
from .errors import ErrorCode, StableError
from .ids import normalize_uuidv7, validate_id


MAX_TOKEN_TTL_US = 60_000_000
MAX_AUTHORIZATION_BYTES = 16 * 1024
CERTIFICATE_DOMAIN = b"agent-meta-service-certificate-v1\0"
TOKEN_DOMAIN = b"agent-meta-execution-token-v1\0"
TOKEN_FIELDS = frozenset({"token_version", "token_id", "backend_session_id", "realm_id", "actor_id", "action_id",
    "effect_kind", "target_scope_hash", "resource_ceiling", "issued_at_us", "expires_at_us", "nonce"})
CERTIFICATE_FIELDS = frozenset({"service_principal_id", "public_key", "realm_id", "epoch_id", "permissions", "not_after"})


def _deny(reason):
    return StableError(code=ErrorCode.AUTHORITY_DENIED, message="execution authorization rejected", details={"reason_code": reason})


def _id(value, prefix):
    try:
        validate_id(value)
        if not value.startswith(prefix + "://"):
            raise ValueError("identity type")
    except (ValueError, TypeError):
        raise _deny("IDENTITY") from None
    return value


def _hex(value, size):
    if not isinstance(value, str) or len(value) != 2 * size or set(value) - set("0123456789abcdef"):
        raise _deny("ENCODING")
    return bytes.fromhex(value)


def _integer(value):
    if type(value) is not int or value < 0 or value > 2**53 - 1:
        raise _deny("INTEGER")
    return value


def _text(value, reason, *, minimum=1, maximum=256):
    if not isinstance(value, str):
        raise _deny(reason)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise _deny(reason) from None
    if not minimum <= size <= maximum or "\0" in value:
        raise _deny(reason)
    return value


def _ceiling(value):
    if not isinstance(value, dict) or not value or len(value) > 32:
        raise _deny("RESOURCE_CEILING")
    result = {}
    for key, number in value.items():
        result[_text(key, "RESOURCE_CEILING", maximum=64)] = _integer(number)
    return dict(sorted(result.items()))


def _certificate_payload(value):
    if not isinstance(value, dict) or set(value) != CERTIFICATE_FIELDS:
        raise _deny("CERTIFICATE_FIELDS")
    _id(value["service_principal_id"], "principal")
    if not value["service_principal_id"].startswith("principal://service/"):
        raise _deny("SERVICE_IDENTITY")
    _id(value["realm_id"], "realm")
    _id(value["epoch_id"], "epoch")
    _hex(value["public_key"], 32)
    _integer(value["not_after"])
    permissions = value["permissions"]
    if not isinstance(permissions, list) or not permissions or not all(isinstance(p, str) and p in PERMISSIONS for p in permissions) or permissions != sorted(set(permissions)):
        raise _deny("CERTIFICATE_PERMISSIONS")
    return value


def _token_payload(value):
    if not isinstance(value, dict) or set(value) != TOKEN_FIELDS or type(value.get("token_version")) is not int or value["token_version"] != 1:
        raise _deny("TOKEN_FIELDS")
    try:
        normalize_uuidv7(value["token_id"])
    except (TypeError, ValueError):
        raise _deny("TOKEN_ID") from None
    _text(value["backend_session_id"], "SESSION")
    _id(value["realm_id"], "realm")
    _id(value["actor_id"], "principal")
    _id(value["action_id"], "action")
    if not isinstance(value["effect_kind"], str) or value["effect_kind"] not in EFFECT_REGISTRY:
        raise _deny("EFFECT")
    _hex(value["target_scope_hash"], 32)
    _ceiling(value["resource_ceiling"])
    issued, expires = _integer(value["issued_at_us"]), _integer(value["expires_at_us"])
    if not 0 < expires - issued <= MAX_TOKEN_TTL_US:
        raise _deny("TOKEN_TTL")
    _text(value["nonce"], "NONCE", minimum=16)
    return value


def _document(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_AUTHORIZATION_BYTES:
        raise _deny("AUTHORIZATION_SIZE")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical_json(value) != raw:
            raise ValueError("noncanonical authorization")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _deny("AUTHORIZATION_ENCODING") from None
    return value


def issue_service_certificate(payload, *, root_principal_id, signer):
    """Public certificate bytes; signer is the operator's scoped callback."""
    _certificate_payload(payload)
    _id(root_principal_id, "principal")
    if not root_principal_id.startswith("principal://operator-root/"):
        raise _deny("ROOT_IDENTITY")
    signature = signer(CERTIFICATE_DOMAIN + canonical_json(payload))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise _deny("SIGNATURE")
    return canonical_json({"schema": "service-execution-certificate/v1", "root_principal_id": root_principal_id,
        "certificate": payload, "signature": signature.hex()})


def issue_execution_token(payload, *, service_principal_id, signer):
    """Enforcement-only bytes, never an Artifact or a Fact payload."""
    _token_payload(payload)
    _id(service_principal_id, "principal")
    if not service_principal_id.startswith("principal://service/"):
        raise _deny("SERVICE_IDENTITY")
    signature = signer(TOKEN_DOMAIN + canonical_json(payload))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise _deny("SIGNATURE")
    return canonical_json({"payload": payload, "service_principal_id": service_principal_id, "signature": signature.hex()})


@dataclass(frozen=True, slots=True)
class ExecutionTokenBinding:
    backend_session_id: str
    realm_id: str
    epoch_id: str
    actor_id: str
    action_id: str
    effect_kind: str
    target_scope_hash: str
    resource_ceiling: Mapping[str, int]
    required_permissions: frozenset[str]
    deadline_at_us: int | None = None

    def __post_init__(self):
        try:
            ceilings = _ceiling(dict(self.resource_ceiling))
            permissions = frozenset(self.required_permissions)
        except (TypeError, ValueError):
            raise _deny("BINDING_FIELDS") from None
        object.__setattr__(self, "resource_ceiling", MappingProxyType(ceilings))
        if not permissions or not permissions <= PERMISSIONS:
            raise _deny("REQUIRED_PERMISSIONS")
        object.__setattr__(self, "required_permissions", permissions)
        _text(self.backend_session_id, "SESSION")
        for name, scheme in (("realm_id", "realm"), ("epoch_id", "epoch"), ("actor_id", "principal"), ("action_id", "action")):
            _id(getattr(self, name), scheme)
        if not isinstance(self.effect_kind, str) or self.effect_kind not in EFFECT_REGISTRY:
            raise _deny("EFFECT")
        _hex(self.target_scope_hash, 32)
        if self.deadline_at_us is not None:
            _integer(self.deadline_at_us)


@dataclass(frozen=True, slots=True)
class ExecutionTokenAudit:
    token_id: str
    payload_hash: str
    service_public_key_id: str
    certificate_artifact_id: str
    request_id: str
    expires_at_us: int


class ExecutionTokenVerifier:
    """Pinned Root chain + strict per-request binding + bounded nonce cache."""

    def __init__(self, *, root_principal_id, root_public_key, realm_id, epoch_id, certificate: bytes,
                 verify_signature: Callable[[bytes, bytes, bytes], bool], maximum_tokens=4096):
        if not isinstance(root_public_key, bytes) or len(root_public_key) != 32:
            raise _deny("ROOT_KEY")
        if type(maximum_tokens) is not int or maximum_tokens <= 0:
            raise _deny("CACHE_LIMIT")
        document = _document(certificate)
        if set(document) != {"schema", "root_principal_id", "certificate", "signature"} or document["schema"] != "service-execution-certificate/v1":
            raise _deny("CERTIFICATE_FIELDS")
        _id(root_principal_id, "principal")
        if not root_principal_id.startswith("principal://operator-root/") or document["root_principal_id"] != root_principal_id:
            raise _deny("ROOT_IDENTITY")
        payload = _certificate_payload(document["certificate"])
        if payload["realm_id"] != realm_id or payload["epoch_id"] != epoch_id:
            raise _deny("CERTIFICATE_SCOPE")
        service_key = _hex(payload["public_key"], 32)
        if service_key == root_public_key:
            raise _deny("SEPARATE_SERVICE_KEY_REQUIRED")
        if verify_signature(root_public_key, CERTIFICATE_DOMAIN + canonical_json(payload), _hex(document["signature"], 64)) is not True:
            raise _deny("CERTIFICATE_SIGNATURE")
        self._certificate = payload
        self._certificate_id = "artifact://sha256/" + sha256_hex(certificate)
        self._service_key = service_key
        self._verify_signature = verify_signature
        self._maximum_tokens = maximum_tokens
        self._tokens = {}
        self._nonces = {}
        self._lock = threading.Lock()

    def verify(self, raw: bytes, *, request_id: str, request_payload_hash: str,
               binding: ExecutionTokenBinding, now_us: int) -> ExecutionTokenAudit:
        _text(request_id, "REQUEST_ID")
        _hex(request_payload_hash, 32)
        _integer(now_us)
        document = _document(raw)
        if set(document) != {"payload", "service_principal_id", "signature"}:
            raise _deny("TOKEN_FIELDS")
        payload = _token_payload(document["payload"])
        certificate = self._certificate
        if document["service_principal_id"] != certificate["service_principal_id"]:
            raise _deny("SERVICE_IDENTITY")
        if self._verify_signature(self._service_key, TOKEN_DOMAIN + canonical_json(payload), _hex(document["signature"], 64)) is not True:
            raise _deny("TOKEN_SIGNATURE")
        if certificate["realm_id"] != binding.realm_id or certificate["epoch_id"] != binding.epoch_id:
            raise _deny("CERTIFICATE_SCOPE")
        if not binding.required_permissions <= set(certificate["permissions"]):
            raise _deny("CERTIFICATE_PERMISSIONS")
        for field in ("backend_session_id", "realm_id", "actor_id", "action_id", "effect_kind", "target_scope_hash"):
            if payload[field] != getattr(binding, field):
                raise _deny("BINDING_" + field.upper())
        if set(payload["resource_ceiling"]) != set(binding.resource_ceiling) or any(
                value > binding.resource_ceiling[key] for key, value in payload["resource_ceiling"].items()):
            raise _deny("RESOURCE_CEILING")
        if not payload["issued_at_us"] <= now_us < payload["expires_at_us"] <= certificate["not_after"]:
            raise _deny("TOKEN_TIME")
        if binding.deadline_at_us is not None and payload["expires_at_us"] > binding.deadline_at_us:
            raise _deny("TASK_DEADLINE")
        token_hash = sha256_hex(canonical_json(payload))
        identity = (request_id, request_payload_hash, token_hash)
        with self._lock:
            self._reserve(payload, identity, now_us)
        return ExecutionTokenAudit(payload["token_id"], token_hash, sha256_hex(self._service_key), self._certificate_id, request_id, payload["expires_at_us"])

    def _reserve(self, payload, identity, now_us):
        expired = [key for key, row in self._tokens.items() if row[1] <= now_us]
        for key in expired:
            self._nonces.pop(self._tokens[key][2], None)
            del self._tokens[key]
        token_id = payload["token_id"]
        nonce_hash = sha256_hex(payload["nonce"].encode("utf-8"))
        previous = self._tokens.get(token_id)
        if previous is not None:
            if previous[0] != identity:
                raise _deny("TOKEN_REPLAY_CONFLICT")
        else:
            if nonce_hash in self._nonces:
                raise _deny("NONCE_REUSED")
            if len(self._tokens) >= self._maximum_tokens:
                raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="execution authorization cache is full")
            self._tokens[token_id] = (identity, payload["expires_at_us"], nonce_hash)
            self._nonces[nonce_hash] = token_id
