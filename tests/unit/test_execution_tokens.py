"""Real Ed25519 chain/token checks; no fixture bypass of worker authorization."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
import threading

import pytest

from agent_meta_runtime.adapters.crypto import Ed25519KeyPair, verify_signature
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.execution_tokens import (CERTIFICATE_DOMAIN, TOKEN_DOMAIN, MAX_TOKEN_TTL_US,
    ExecutionTokenBinding, ExecutionTokenVerifier, issue_execution_token, issue_service_certificate)
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7


NOW = 1_800_000_000_000_000
ROOT = "principal://operator-root/01900000-0000-7000-8000-000000000000"
SERVICE = "principal://service/01900000-0000-7000-8000-000000000001"
ACTOR = "principal://agent/01900000-0000-7000-8000-000000000002"
EPOCH = "epoch://01900000-0000-7000-8000-000000000003"
ACTION = "action://01900000-0000-7000-8000-000000000004"


class Chain:
    def __init__(self, *, certificate_changes=None, maximum_tokens=4096):
        self.root = Ed25519KeyPair.from_private_bytes(bytes(range(32)))
        self.service = Ed25519KeyPair.from_private_bytes(bytes(range(32, 64)))
        self.certificate = {"service_principal_id": SERVICE, "public_key": self.service.public_bytes_raw().hex(),
            "realm_id": "realm://main", "epoch_id": EPOCH, "permissions": ["capability.invoke", "model.invoke"],
            "not_after": NOW + 86_400_000_000, **(certificate_changes or {})}
        self.raw_certificate = issue_service_certificate(self.certificate, root_principal_id=ROOT, signer=self.root.sign)
        self.verifier = self.make_verifier(maximum_tokens=maximum_tokens)
        self.binding = ExecutionTokenBinding("actual-session", "realm://main", EPOCH, ACTOR, ACTION, "model.invoke",
            sha256_hex(b"frozen-target-scope"), {"model_calls": 1, "cost_microunits": 0}, frozenset({"model.invoke"}))
        self.payload = {"token_version": 1, "token_id": new_uuid7(), "backend_session_id": self.binding.backend_session_id,
            "realm_id": self.binding.realm_id, "actor_id": self.binding.actor_id, "action_id": self.binding.action_id,
            "effect_kind": self.binding.effect_kind, "target_scope_hash": self.binding.target_scope_hash,
            "resource_ceiling": dict(self.binding.resource_ceiling), "issued_at_us": NOW, "expires_at_us": NOW + 60_000_000,
            "nonce": "n" * 32}

    def make_verifier(self, **kwargs):
        return ExecutionTokenVerifier(root_principal_id=ROOT, root_public_key=self.root.public_bytes_raw(), realm_id="realm://main",
            epoch_id=EPOCH, certificate=self.raw_certificate, verify_signature=verify_signature, **kwargs)

    def token(self, **changes):
        return issue_execution_token({**self.payload, **changes}, service_principal_id=SERVICE, signer=self.service.sign)

    def signed_unchecked(self, **changes):
        payload = {**self.payload, **changes}
        return canonical_json({"payload": payload, "service_principal_id": SERVICE,
            "signature": self.service.sign(TOKEN_DOMAIN + canonical_json(payload)).hex()})

    def verify(self, raw=None, **changes):
        return self.verifier.verify(self.token() if raw is None else raw, request_id=changes.pop("request_id", "request-one"),
            request_payload_hash=changes.pop("request_payload_hash", sha256_hex(b"normalized request")),
            binding=changes.pop("binding", self.binding), now_us=changes.pop("now_us", NOW), **changes)


def test_real_chain_allows_exact_replay_and_returns_only_public_audit_metadata():
    chain = Chain()
    raw = chain.token()
    first = chain.verify(raw)
    assert first == chain.verify(raw)
    value = asdict(first)
    assert set(value) == {"token_id", "payload_hash", "service_public_key_id", "certificate_artifact_id", "request_id", "expires_at_us"}
    assert value["payload_hash"] == sha256_hex(canonical_json(chain.payload))
    assert value["certificate_artifact_id"] == "artifact://sha256/" + sha256_hex(chain.raw_certificate)
    assert chain.payload["nonce"] not in repr(first) and chain.token().decode() not in repr(first)
    assert len(chain.verifier._tokens) == len(chain.verifier._nonces) == 1


@pytest.mark.parametrize("dimension,value", [
    ("backend_session_id", "other-session"), ("realm_id", "realm://other"),
    ("actor_id", "principal://agent/01900000-0000-7000-8000-000000000009"),
    ("action_id", "action://01900000-0000-7000-8000-000000000009"), ("effect_kind", "filesystem.write"),
    ("target_scope_hash", "0" * 64), ("resource_ceiling", {"model_calls": 2, "cost_microunits": 0}),
    ("resource_ceiling", {"model_calls": 1}), ("resource_ceiling", {"model_calls": 1, "cost_microunits": 1}),
])
def test_valid_signature_cannot_expand_or_substitute_worker_binding(dimension, value):
    chain = Chain()
    with pytest.raises(StableError) as error:
        chain.verify(chain.token(**{dimension: value}))
    assert error.value.code == ErrorCode.AUTHORITY_DENIED
    assert not chain.verifier._tokens


@pytest.mark.parametrize("changes", [
    {"token_version": True}, {"token_version": 2}, {"token_id": "not-a-uuid"}, {"nonce": "short"},
    {"issued_at_us": True}, {"expires_at_us": NOW + 10.5}, {"expires_at_us": NOW},
    {"expires_at_us": NOW + MAX_TOKEN_TTL_US + 1}, {"resource_ceiling": {}},
    {"resource_ceiling": {"model_calls": True}}, {"resource_ceiling": {"model_calls": -1}},
    {"effect_kind": "unknown.effect"}, {"target_scope_hash": "A" * 64}, {"extra": True},
])
def test_even_signed_malformed_claims_are_rejected_without_cache_use(changes):
    chain = Chain()
    with pytest.raises(StableError) as error:
        chain.verify(chain.signed_unchecked(**changes))
    assert error.value.code == ErrorCode.AUTHORITY_DENIED and not chain.verifier._tokens


@pytest.mark.parametrize("case", ["expired", "future", "certificate_expiry", "deadline", "zero_deadline", "epoch", "permission"])
def test_time_epoch_and_certificate_permission_boundaries(case):
    chain = Chain(certificate_changes={"not_after": NOW + 59_000_000} if case == "certificate_expiry" else None)
    values = {}
    if case == "expired":
        values["now_us"] = NOW + MAX_TOKEN_TTL_US
    elif case == "future":
        values["now_us"] = NOW - 1
    elif case in ("deadline", "zero_deadline"):
        values["binding"] = replace(chain.binding, deadline_at_us=NOW + MAX_TOKEN_TTL_US - 1 if case == "deadline" else 0)
    elif case == "epoch":
        values["binding"] = replace(chain.binding, epoch_id="epoch://" + new_uuid7())
    elif case == "permission":
        values["binding"] = replace(chain.binding, required_permissions=frozenset({"state.write"}))
    with pytest.raises(StableError) as error:
        chain.verify(**values)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED and not chain.verifier._tokens


@pytest.mark.parametrize("case", ["root_key", "root_id", "realm", "epoch", "signature", "same_key", "noncanonical"])
def test_certificate_chain_requires_pinned_root_scope_and_distinct_service_key(case):
    chain = Chain()
    values = {"root_principal_id": ROOT, "root_public_key": chain.root.public_bytes_raw(), "realm_id": "realm://main",
        "epoch_id": EPOCH, "certificate": chain.raw_certificate, "verify_signature": verify_signature}
    if case == "root_key":
        values["root_public_key"] = chain.service.public_bytes_raw()
    elif case == "root_id":
        values["root_principal_id"] = "principal://operator-root/" + new_uuid7()
    elif case == "realm":
        values["realm_id"] = "realm://other"
    elif case == "epoch":
        values["epoch_id"] = "epoch://" + new_uuid7()
    elif case == "signature":
        document = json.loads(chain.raw_certificate)
        document["certificate"]["not_after"] += 1
        values["certificate"] = canonical_json(document)
    elif case == "same_key":
        values["certificate"] = issue_service_certificate({**chain.certificate, "public_key": chain.root.public_bytes_raw().hex()},
            root_principal_id=ROOT, signer=chain.root.sign)
    else:
        values["certificate"] += b" "
    with pytest.raises(StableError) as error:
        ExecutionTokenVerifier(**values)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED


@pytest.mark.parametrize("case", ["signature", "service", "noncanonical", "duplicate_field", "oversized", "empty", "private_diagnostic"])
def test_malformed_token_bytes_never_expose_serialized_authorization(case):
    chain = Chain()
    document = json.loads(chain.token())
    if case == "signature":
        document["payload"]["nonce"] = "altered" * 6
    elif case == "service":
        document["service_principal_id"] = "principal://service/" + new_uuid7()
    raw = canonical_json(document)
    if case == "noncanonical":
        raw += b" "
    elif case == "duplicate_field":
        raw = raw[:-1] + b',"signature":"' + document["signature"].encode() + b'"}'
    elif case == "oversized":
        raw = b"x" * 16385
    elif case == "empty":
        raw = b""
    elif case == "private_diagnostic":
        raw = b'{"secret":"unique-secret-marker",'
    with pytest.raises(StableError) as error:
        chain.verify(raw)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED
    assert "unique-secret-marker" not in str(error.value)
    assert not raw or raw.decode(errors="replace") not in str(error.value)
    assert not chain.verifier._tokens


@pytest.mark.parametrize("case", ["request", "payload", "claims", "nonce"])
def test_token_id_or_nonce_cannot_authorize_another_request(case):
    chain = Chain()
    chain.verify()
    raw, options = chain.token(), {}
    if case == "request":
        options["request_id"] = "request-two"
    elif case == "payload":
        options["request_payload_hash"] = sha256_hex(b"different request")
    elif case == "claims":
        raw = chain.token(nonce="different-valid-nonce" * 2)
    else:
        raw = chain.token(token_id=new_uuid7())
    with pytest.raises(StableError) as error:
        chain.verify(raw, **options)
    assert error.value.code == ErrorCode.AUTHORITY_DENIED and len(chain.verifier._tokens) == 1


def test_cache_capacity_fails_closed_and_expired_records_can_be_pruned():
    chain = Chain(maximum_tokens=1)
    chain.verify()
    with pytest.raises(StableError) as error:
        chain.verify(chain.token(token_id=new_uuid7(), nonce="second-valid-nonce" * 2), request_id="two")
    assert error.value.code == ErrorCode.RESOURCE_EXHAUSTED
    later = NOW + MAX_TOKEN_TTL_US
    raw = chain.token(token_id=new_uuid7(), nonce="third-valid-nonce" * 2, issued_at_us=later, expires_at_us=later + 1000)
    assert chain.verify(raw, request_id="three", now_us=later).request_id == "three"
    assert len(chain.verifier._tokens) == len(chain.verifier._nonces) == 1


def test_issuer_rejects_integral_float_before_jcs_can_normalize_its_spelling():
    chain = Chain()
    with pytest.raises(StableError) as error:
        chain.token(expires_at_us=float(NOW + 10))
    assert error.value.code == ErrorCode.AUTHORITY_DENIED


def test_concurrent_workers_cannot_consume_one_token_for_different_requests():
    chain = Chain()
    raw, barrier = chain.token(), threading.Barrier(16)
    def verify(index):
        barrier.wait()
        try:
            return chain.verify(raw, request_id=f"concurrent-{index}")
        except StableError as error:
            assert error.code == ErrorCode.AUTHORITY_DENIED
            return None
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(verify, range(16)))
    assert sum(value is not None for value in results) == 1
    assert len(chain.verifier._tokens) == len(chain.verifier._nonces) == 1
