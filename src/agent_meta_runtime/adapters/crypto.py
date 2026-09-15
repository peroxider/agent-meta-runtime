"""Ed25519 identity primitives for Root/Service Principals (§41.16, §41.28).

Thin adapter over the ``cryptography`` package. The Meta Store only ever sees
raw public keys, their SHA-256 fingerprints and credential handles — private
key material stays in the OS keychain or, in explicitly insecure dev mode, a
``0600`` credential file. Signature preimages are pure domain functions in
``domain.authority``.
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..domain.canonical import sha256_hex

__all__ = [
    "Ed25519KeyPair",
    "verify_signature",
    "public_key_fingerprint",
    "generate_recovery_code",
    "root_recovery_hash",
    "RECOVERY_PREIMAGE_DOMAIN",
]

RECOVERY_PREIMAGE_DOMAIN = b"agent-meta-root-recovery-v1\x00"


class Ed25519KeyPair:
    """A generation-capable handle around an Ed25519 private key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Ed25519KeyPair":
        if not isinstance(raw, bytes) or len(raw) != 32:
            raise ValueError("Ed25519 private key must be 32 raw bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def private_bytes_raw(self) -> bytes:
        raw = self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return bytes(raw)

    def public_bytes_raw(self) -> bytes:
        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return bytes(raw)

    def sign(self, message: bytes) -> bytes:
        return bytes(self._private.sign(message))


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature; malformed inputs verify False."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def public_key_fingerprint(public_key: bytes) -> str:
    """SHA-256 fingerprint over the raw public key bytes (§41.28)."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("raw Ed25519 public key must be 32 bytes")
    return sha256_hex(public_key)


def generate_recovery_code() -> str:
    """256-bit one-time recovery code, shown to the operator exactly once."""

    return secrets.token_urlsafe(32)


def root_recovery_hash(raw_code: str) -> str:
    """Stored hash: ``sha256(domain + raw code)`` — the raw code is never
    persisted, logged or included in diagnostics (§41.28)."""

    if not raw_code:
        raise ValueError("recovery code must be non-empty")
    return sha256_hex(RECOVERY_PREIMAGE_DOMAIN + raw_code.encode("utf-8"))
