"""Public, offline package authoring API (Harness Contract 1.1.0).

No code is loaded or executed by these helpers. Validation by a connected
Runtime remains necessary before installation or activation.
"""

from ..domain.ampak import (
    AmpakError,
    PackageEntry,
    PackageManifest,
    PackageMeta,
    build_manifest,
    decode_package,
    encode_package,
    validate_package_path,
)
from ..domain.canonical import canonical_json, sha256_hex
from ..domain.harness import (
    contract_fingerprint,
    manifest_signature_preimage,
    validate_grant_requests,
    validate_loop_policy,
    validate_manifest,
)

HARNESS_CONTRACT_VERSION = "1.1.0"

__all__ = [
    "HARNESS_CONTRACT_VERSION", "AmpakError", "PackageEntry", "PackageManifest",
    "PackageMeta", "build_manifest", "decode_package", "encode_package",
    "validate_package_path", "canonical_json", "sha256_hex",
    "contract_fingerprint", "manifest_signature_preimage", "validate_manifest",
    "validate_loop_policy", "validate_grant_requests",
]
