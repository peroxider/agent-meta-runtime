"""Truthful feature identity of the currently assembled in-process Host."""

from types import MappingProxyType
import json

from .canonical import canonical_json, sha256_hex


TRUSTED_HOST_BACKEND_FEATURES = MappingProxyType({name: "UNSUPPORTED" for name in (
    "process", "activity", "channel", "workspace", "persistent_idempotency",
    "isolated_realm", "network_isolation", "credential_isolation", "hard_memory_quota")})
TRUSTED_HOST_PROFILE_CONTENT = canonical_json({
    "schema": "host-execution-profile/v1", "placement": "in_process",
    "publisher_trust": "EXPLICIT", "isolation": "NONE", "cancellation": "COOPERATIVE",
    "model_cost": "EXPLICIT_ZERO_ONLY", "tool_idempotency": "PURE",
    "context_tokenizer": "utf8-bytes/v1", "context_ceiling_bytes": 1024 * 1024,
    "context_contract": "context-profile/v1", "context_verification": "RECOMPUTE_FROZEN_SOURCES",
    "projection_manifest": "required-fields/v1",
    "harness_lifecycle": "OWNERSHIP_AND_GRANT_GENERATIONS_V1",
    "backend_features": dict(TRUSTED_HOST_BACKEND_FEATURES),
})
TRUSTED_HOST_PROFILE_HASH = sha256_hex(TRUSTED_HOST_PROFILE_CONTENT)

INMEMORY_HOST_BACKEND_FEATURES = MappingProxyType({**dict(TRUSTED_HOST_BACKEND_FEATURES),
    "process": "SUPPORTED", "activity": "SUPPORTED", "channel": "SUPPORTED", "persistent_idempotency": "EMULATED"})
INMEMORY_HOST_PROFILE_CONTENT = canonical_json({
    "schema": "host-execution-profile/v1", "placement": "in_process", "publisher_trust": "EXPLICIT",
    "isolation": "NONE", "cancellation": "COOPERATIVE", "model_cost": "EXPLICIT_ZERO_ONLY", "tool_idempotency": "PURE",
    "context_tokenizer": "utf8-bytes/v1", "context_ceiling_bytes": 1024 * 1024, "context_contract": "context-profile/v1",
    "context_verification": "RECOMPUTE_FROZEN_SOURCES", "projection_manifest": "required-fields/v1",
    "harness_lifecycle": "OWNERSHIP_AND_GRANT_GENERATIONS_V1", "execution_backend": "backend://inmemory",
    "execution_authorization": "ROOT_CERTIFIED_SERVICE_TOKEN_V1", "terminal_ack": "DURABLE_OUTBOX_V1",
    "backend_features": dict(INMEMORY_HOST_BACKEND_FEATURES)})
INMEMORY_HOST_PROFILE_HASH = sha256_hex(INMEMORY_HOST_PROFILE_CONTENT)

CONTROLLED_PROVIDER_HOST_PROFILE_CONTENT = canonical_json({
    **json.loads(TRUSTED_HOST_PROFILE_CONTENT),
    'model_cost':'FROZEN_TEST_PRICE_RESERVATION_V2',
    'provider_execution':'CONTROLLED_TEST_ONLY', 'provider_network':'LOOPBACK_ONLY',
    'provider_currency':'TEST', 'provider_worker':'ROOT_CERTIFIED_OWNED_PROCESS_V1',
    'provider_approval':'FROZEN_FACT_AND_CURRENT_BINDING',
})
CONTROLLED_PROVIDER_HOST_PROFILE_HASH = sha256_hex(CONTROLLED_PROVIDER_HOST_PROFILE_CONTENT)
