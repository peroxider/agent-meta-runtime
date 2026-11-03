"""Authority/signature/revision checks for public command transactions.

Preview is read-only. The same check runs under BEGIN IMMEDIATE before the
mutator; one use is reserved before the business mutation in that transaction.
The UoW's replay lookup runs first, so a committed command can recover its
original receipt even after grant revocation or a subsequent revision change.
"""

from __future__ import annotations

import json

from ...domain.authority import ScopeTarget, authorize, command_signature_preimage
from ...domain.canonical import sha256_hex
from ...domain.command_policy import COMMAND_PERMISSIONS
from ...domain.envelope import command_authorization_hash
from ...domain.errors import ErrorCode, StableError
from ..crypto import verify_signature
from .authority import load_grant_row, _reserve_use_row

def _deny(reason):
    return StableError(code=ErrorCode.AUTHORITY_DENIED, message="command authority rejected", details={"reason_code": reason})


def command_target(envelope, conn=None):
    payload = envelope.payload
    if envelope.payload_type in ('state.create/v1','state.read/v1','state.write/v1') and conn is not None:
        from .state_management import command_target as state_target
        return state_target(conn,envelope)
    if envelope.payload_type == "authority.delegate/v1":
        scope = payload.get("scope")
        targets = scope.get("targets") if isinstance(scope, dict) else None
        if isinstance(targets, list) and targets and isinstance(targets[0], dict) and not set(targets[0]) - {"type", "id"}:
            return ScopeTarget(**targets[0])
        return None
    if envelope.payload_type == "authority.revoke/v1" and conn is not None:
        grant_id = payload.get("grant_id")
        grant = load_grant_row(conn, grant_id) if isinstance(grant_id, str) else None
        if grant is not None and grant.scope.realm_id == envelope.realm_id and grant.scope.targets:
            return grant.scope.targets[0]
        return None
    if envelope.payload_type in ("harness.activate/v1", "harness.configure-provider/v1", "harness.deactivate/v1", "harness.uninstall/v1"):
        return ScopeTarget("HARNESS", str(payload.get("harness_id", "")))
    if envelope.payload_type == "task.cancel/v1":
        return ScopeTarget("TASK", str(payload.get("task_id", "")))
    if envelope.payload_type == "artifact.put/v1":
        return ScopeTarget("ARTIFACT_KIND", str(payload.get("kind", "")))
    return None


def _verify_identity(conn, envelope, *, now_us, replay=False):
    principal = conn.execute(
        "SELECT public_identity_json, status FROM principals WHERE principal_id=? AND realm_id=?",
        (envelope.actor_id, envelope.realm_id),
    ).fetchone()
    if principal is None or (not replay and principal[1] != "ACTIVE"):
        raise _deny("ACTIVE_PRINCIPAL_REQUIRED")
    nonce, issued, signature = envelope.auth_nonce, envelope.auth_issued_at_us, envelope.auth_signature
    if (not isinstance(nonce, str) or not 16 <= len(nonce.encode("utf-8")) <= 256
            or type(issued) is not int or not isinstance(signature, bytes) or len(signature) != 64):
        raise _deny("SIGNATURE_REQUIRED")
    if not replay and abs(now_us - issued) > 300_000_000:
        raise _deny("SIGNATURE_STALE")
    try:
        identity = json.loads(principal[0])
        public_key = bytes.fromhex(identity["public_key_hex"])
        if identity.get("algorithm") != "Ed25519":
            raise ValueError("unsupported identity algorithm")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise _deny("PUBLIC_IDENTITY_INVALID") from exc
    if not verify_signature(public_key, command_signature_preimage(command_authorization_hash(envelope), nonce, issued), signature):
        raise _deny("SIGNATURE_INVALID")


def authorize_public_command(conn, envelope, *, now_us: int, replay_lookup: bool = False):
    if replay_lookup:
        row = conn.execute("SELECT authorization_hash FROM commands WHERE command_id=?", (envelope.command_id,)).fetchone()
        if row is not None:
            if row[0] != command_authorization_hash(envelope):
                raise StableError(code=ErrorCode.IDEMPOTENCY_CONFLICT, message="command identity has different authorization/payload")
            # Replay bypasses mutable grant/revision state, never identity proof.
            _verify_identity(conn, envelope, now_us=now_us, replay=True)
            return None
    permission = COMMAND_PERMISSIONS.get(envelope.payload_type)
    if permission is None:
        raise _deny("UNKNOWN_COMMAND_PERMISSION")
    realm = conn.execute("SELECT epoch_id, current_meta_revision FROM realms WHERE realm_id=?", (envelope.realm_id,)).fetchone()
    _verify_identity(conn, envelope, now_us=now_us)
    if realm is None or envelope.authority_grant_id is None:
        raise _deny("EXPLICIT_PRINCIPAL_AND_GRANT_REQUIRED")
    grant = load_grant_row(conn, envelope.authority_grant_id)
    if grant is None:
        raise _deny("GRANT_NOT_FOUND")
    uses = conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (grant.grant_id,)).fetchone()[0]
    try:
        reason = authorize(grant, subject_id=envelope.actor_id, permission=permission,
                            resource_realm=envelope.realm_id, resource_target=command_target(envelope, conn),
                           epoch_id=realm[0], now_us=now_us, uses_count=uses)
    except (ValueError, TypeError, AttributeError) as exc:
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="command resource scope invalid") from exc
    if reason is not None:
        raise _deny(reason)
    if grant.epoch_id != realm[0]:
        raise _deny("EPOCH")
    if conn.execute("SELECT 1 FROM commands WHERE realm_id=? AND auth_nonce_hash=?", (envelope.realm_id, sha256_hex(envelope.auth_nonce.encode("utf-8")))).fetchone():
        raise _deny("NONCE_REUSED")
    if envelope.expected_meta_revision is not None and envelope.expected_meta_revision != realm[1]:
        raise StableError(code=ErrorCode.REVISION_CONFLICT, message="command expected meta revision differs", details={"expected": envelope.expected_meta_revision, "actual": realm[1]})
    return grant


def guard_public_command(envelope, mutator):
    def guarded(txn):
        grant = authorize_public_command(txn._conn, envelope, now_us=txn.recorded_at_us)
        if not _reserve_use_row(txn, grant.grant_id, envelope.command_id, "command", {}):
            raise _deny("COMMAND_USE_ALREADY_RESERVED")
        return mutator(txn)
    return guarded
