"""Ordinary identities and bounded public delegation, never system identity setup."""

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.ids import new_uuid7
from ...domain.principal_contract import (ORDINARY_PRINCIPAL_KINDS, delegation_payload,
    principal_registration, revocation_payload)
from .authority import (CreateGrantRequest, RevokeGrantRequest, _append_fact, create_grant,
    load_grant_row, revoke_grant)


def _ordinary(conn, realm_id, subject_id, *, require_active=True):
    row = conn.execute("SELECT kind,status FROM principals WHERE principal_id=? AND realm_id=?", (subject_id, realm_id)).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.NOT_FOUND, message="ordinary principal not found in this realm")
    if row[0] not in ORDINARY_PRINCIPAL_KINDS:
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="system principals require their dedicated lifecycle")
    if require_active and row[1] != "ACTIVE":
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="ordinary principal is not active")


def register_principal(payload):
    requested_id, kind, key = principal_registration(payload)
    identity = {"algorithm": "Ed25519", "public_key_hex": key.hex(), "key_fingerprint": sha256_hex(key)}
    encoded = canonical_json(identity)
    def register(txn):
        principal_id = requested_id or f"principal://{kind.lower()}/{new_uuid7()}"
        existing = txn._conn.execute("SELECT realm_id,kind,public_identity_json,status FROM principals WHERE principal_id=?", (principal_id,)).fetchone()
        if existing is not None:
            if existing[:2] != (txn._envelope.realm_id, kind) or bytes(existing[2]) != encoded:
                raise StableError(code=ErrorCode.ALREADY_EXISTS, message="PrincipalId already has a different immutable identity")
            status = existing[3]
        else:
            txn._conn.execute("INSERT INTO principals(principal_id,realm_id,kind,public_identity_json,status,created_at_us) VALUES (?,?,?,?,'ACTIVE',?)",
                (principal_id, txn._envelope.realm_id, kind, encoded, txn.recorded_at_us))
            _append_fact(txn, entity_type="authority", entity_id=principal_id, event_type="principal_registered",
                payload={"principal_id": principal_id, "kind": kind, "public_identity": identity}, actor_id=txn._envelope.actor_id)
            status = "ACTIVE"
        return {"principal_id": principal_id, "realm_id": txn._envelope.realm_id, "kind": kind,
            "public_identity": identity, "status": status}
    return register


def _grant_resource(grant):
    return {"grant_id": grant.grant_id, "parent_grant_id": grant.parent_grant_id, "epoch_id": grant.epoch_id,
        "issuer_id": grant.issuer_id, "subject_id": grant.subject_id, "permissions": sorted(grant.permissions),
        "scope": grant.scope.to_json(), "constraints": grant.constraints.to_json(), "delegable": grant.delegable,
        "delegation_depth": grant.delegation_depth, "status": grant.status, "issued_at_us": grant.issued_at_us}


def delegate_ordinary_grant(payload, *, realm_id):
    subject, permissions, scope, constraints, delegable = delegation_payload(payload, realm_id=realm_id)
    def delegate(txn):
        _ordinary(txn._conn, realm_id, subject)
        result = create_grant(CreateGrantRequest(issuer_grant_id=txn._envelope.authority_grant_id,
            subject_id=subject, permissions=permissions, scope=scope, constraints=constraints, delegable=delegable))(txn)
        return _grant_resource(load_grant_row(txn._conn, result["grant_id"]))
    return delegate


def revoke_ordinary_grant(payload):
    grant_id, reason = revocation_payload(payload)
    def revoke(txn):
        grant = load_grant_row(txn._conn, grant_id)
        if grant is None or grant.scope.realm_id != txn._envelope.realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND, message="grant not found in this realm")
        _ordinary(txn._conn, txn._envelope.realm_id, grant.subject_id, require_active=False)
        if grant.parent_grant_id is None:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="root grants require their dedicated lifecycle")
        actor = txn._conn.execute("SELECT kind FROM principals WHERE principal_id=? AND realm_id=?", (txn._envelope.actor_id, txn._envelope.realm_id)).fetchone()
        if actor is None or actor[0] != "OPERATOR_ROOT" and txn._envelope.actor_id not in (grant.issuer_id, grant.subject_id):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="caller does not own this delegation")
        authority = load_grant_row(txn._conn, txn._envelope.authority_grant_id)
        if authority is None or not authority.scope.contains(grant.scope):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="revocation exceeds the caller's authority scope")
        revoke_grant(RevokeGrantRequest(grant_id, reason))(txn)
        return _grant_resource(load_grant_row(txn._conn, grant_id))
    return revoke
