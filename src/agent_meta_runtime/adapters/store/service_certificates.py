"""Load only public execution trust data, pinned to the stored Realm/Epoch."""

from dataclasses import dataclass
import json

from ...domain.errors import ErrorCode, StableError
from ...domain.execution_tokens import ExecutionTokenVerifier, MAX_AUTHORIZATION_BYTES
from ..crypto import verify_signature


@dataclass(frozen=True, slots=True)
class ServiceExecutionTrust:
    service_principal_id: str
    service_public_key: bytes
    certificate_artifact_id: str
    certificate: bytes
    expires_at_us: int
    verifier: ExecutionTokenVerifier


def load_service_execution_trust(conn, cas, *, realm_id, now_us=None):
    realm = conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (realm_id,)).fetchone()
    initialization = conn.execute("SELECT payload_json FROM facts WHERE realm_id=? AND event_type='runtime_initialized' ORDER BY seq LIMIT 1", (realm_id,)).fetchone()
    if realm is None or initialization is None:
        raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="execution trust has no initialized Realm")
    try:
        initialized = json.loads(initialization[0])
        reference = initialized.get("service_certificate_artifact_id")
        if reference is None:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="execution Service certificate is unavailable; explicit certificate setup is required")
        epoch = conn.execute("SELECT authority_root_principal_id FROM epochs WHERE realm_id=? AND epoch_id=?", (realm_id, realm[0])).fetchone()
        if epoch is None:
            raise ValueError("missing current Epoch")
        service_id = initialized["service_principal_id"]
        keys = {}
        for kind, principal in (("OPERATOR_ROOT", epoch[0]), ("SERVICE", service_id)):
            row = conn.execute("SELECT kind,status,public_identity_json FROM principals WHERE principal_id=? AND realm_id=?", (principal, realm_id)).fetchone()
            if row is None or row[:2] != (kind, "ACTIVE"):
                raise ValueError("inactive trust identity")
            identity = json.loads(row[2])
            if identity["algorithm"] != "Ed25519":
                raise ValueError("unsupported trust identity")
            raw_key = bytes.fromhex(identity["public_key_hex"])
            if len(raw_key) != 32 or raw_key.hex() != identity["public_key_hex"]:
                raise ValueError("invalid trust public key")
            keys[kind] = raw_key
        row = conn.execute("SELECT kind,size_bytes,manifest_json,integrity_status FROM artifacts WHERE artifact_id=?", (reference,)).fetchone()
        if row is None or row[0] != "authority_certificate" or row[3] != "VALID" or not 0 < row[1] <= MAX_AUTHORIZATION_BYTES:
            raise ValueError("invalid certificate Artifact")
        manifest = json.loads(row[2])
        raw = cas.open_blob(manifest["storage_relpath"], reference.rsplit("/", 1)[1], row[1])
        verifier = ExecutionTokenVerifier(root_principal_id=epoch[0], root_public_key=keys["OPERATOR_ROOT"], realm_id=realm_id,
            epoch_id=realm[0], certificate=raw, verify_signature=verify_signature)
        payload = json.loads(raw)["certificate"]
        if payload["service_principal_id"] != service_id or payload["public_key"] != keys["SERVICE"].hex():
            raise ValueError("certificate Service identity mismatch")
        if now_us is not None and now_us >= payload["not_after"]:
            raise StableError(code=ErrorCode.KEY_UNAVAILABLE, message="execution Service certificate has expired")
        return ServiceExecutionTrust(service_id, keys["SERVICE"], reference, raw, payload["not_after"], verifier)
    except StableError as exc:
        if exc.code == ErrorCode.KEY_UNAVAILABLE:
            raise
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="stored execution certificate trust is invalid") from None
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="stored execution certificate trust is invalid") from None
