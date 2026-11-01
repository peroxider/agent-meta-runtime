"""Public, replayable command representation and opaque signing callbacks."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
import json
import secrets
from typing import Callable, Mapping, Any

from ..domain.authority import command_signature_preimage
from ..domain.canonical import canonical_json, now_us
from ..domain.envelope import CommandEnvelope, command_authorization_hash
from ..domain.ids import validate_id

COMMAND_FIELDS = frozenset({
    "command_id", "realm_id", "actor_id", "authority_grant_id", "expected_meta_revision",
    "causal_parent_action_id", "payload_type", "payload_schema_version", "payload",
    "auth_nonce", "auth_issued_at_us", "auth_signature",
})


@dataclass(frozen=True, slots=True)
class CommandAuthority:
    actor_id: str
    authority_grant_id: str
    signer: Callable[[bytes], bytes] = field(repr=False, compare=False)

    def __post_init__(self):
        validate_id(self.actor_id)
        validate_id(self.authority_grant_id)
        if not self.actor_id.startswith("principal://") or not self.authority_grant_id.startswith("grant://") or not callable(self.signer):
            raise ValueError("command authority requires exact public identity/grant and a signer")


def encode_command(envelope: CommandEnvelope) -> str:
    body = {name: getattr(envelope, name) for name in COMMAND_FIELDS}
    body["payload"] = dict(envelope.payload)
    body["auth_signature"] = None if envelope.auth_signature is None else base64.b64encode(envelope.auth_signature).decode("ascii")
    return canonical_json(body).decode("utf-8")


def decode_command(raw: str | bytes) -> CommandEnvelope:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate command field")
            result[key] = value
        return result

    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, bytes) or len(raw) > 16 * 1024 * 1024:
        raise ValueError("invalid command encoding/size")
    body = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(body, dict) or set(body) != COMMAND_FIELDS or not isinstance(body["payload"], dict) or canonical_json(body) != raw:
        raise ValueError("command must contain the exact fields as canonical JSON")
    signature = body["auth_signature"]
    if signature is not None:
        if not isinstance(signature, str):
            raise ValueError("signature must be base64")
        body["auth_signature"] = base64.b64decode(signature, validate=True)
        if len(body["auth_signature"]) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes")
    return CommandEnvelope(**body)


def sign_command(envelope: CommandEnvelope, authority: CommandAuthority, *, nonce: str | None = None, issued_at_us: int | None = None) -> CommandEnvelope:
    if envelope.actor_id != authority.actor_id or envelope.authority_grant_id != authority.authority_grant_id:
        raise ValueError("signing authority differs from command identity/grant")
    nonce = secrets.token_urlsafe(32) if nonce is None else nonce
    issued_at_us = now_us() if issued_at_us is None else issued_at_us
    signature = authority.signer(command_signature_preimage(command_authorization_hash(envelope), nonce, issued_at_us))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("signer must return a 64-byte Ed25519 signature")
    return replace(envelope, auth_nonce=nonce, auth_issued_at_us=issued_at_us, auth_signature=signature)
