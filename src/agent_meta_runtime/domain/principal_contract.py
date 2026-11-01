"""Strict ordinary-identity/delegation payloads for Public API 1.4."""

from .authority import GrantConstraints, PERMISSIONS, Scope, ScopeTarget
from .errors import ErrorCode, StableError
from .ids import validate_id


ORDINARY_PRINCIPAL_KINDS = frozenset({"AGENT", "CAPABILITY", "PEER"})


def invalid(message):
    return StableError(code=ErrorCode.INVALID_ARGUMENT, message=message)


def principal_registration(payload):
    if not isinstance(payload, dict) or set(payload) - {"principal_id", "kind", "public_key_hex"}:
        raise invalid("unsupported principal registration fields")
    kind, identity, key = payload.get("kind"), payload.get("principal_id"), payload.get("public_key_hex")
    if not isinstance(kind, str) or kind not in ORDINARY_PRINCIPAL_KINDS:
        raise invalid("only ordinary AGENT/CAPABILITY/PEER identities can be registered")
    if identity is not None:
        try:
            validate_id(identity)
        except (TypeError, ValueError) as exc:
            raise invalid("invalid ordinary PrincipalId") from exc
        if not identity.startswith("principal://" + kind.lower() + "/"):
            raise invalid("PrincipalId kind does not match registration")
    try:
        if not isinstance(key, str) or len(key) != 64:
            raise ValueError("key size")
        raw = bytes.fromhex(key)
        if raw.hex() != key or len(raw) != 32:
            raise ValueError("key encoding")
    except ValueError as exc:
        raise invalid("principal public key must be 32 lowercase hex-encoded Ed25519 bytes") from exc
    return identity, kind, raw


def delegation_payload(payload, *, realm_id):
    if not isinstance(payload, dict) or set(payload) - {"subject_id", "permissions", "scope", "constraints", "delegable"}:
        raise invalid("unsupported delegation fields")
    subject, permissions = payload.get("subject_id"), payload.get("permissions")
    try:
        validate_id(subject)
    except (TypeError, ValueError) as exc:
        raise invalid("invalid delegation subject") from exc
    if not subject.startswith("principal://") or not isinstance(permissions, list) or not permissions or not all(isinstance(p, str) and p in PERMISSIONS for p in permissions) or permissions != sorted(set(permissions)):
        raise invalid("delegation requires a PrincipalId and sorted unique known permissions")
    value, constraints, delegable = payload.get("scope"), payload.get("constraints", {}), payload.get("delegable", False)
    if not isinstance(value, dict) or set(value) != {"realm_id", "targets"} or value["realm_id"] != realm_id or not isinstance(value["targets"], list):
        raise invalid("delegation scope must be a typed scope in this realm")
    try:
        if not value["targets"] or any(not isinstance(t, dict) or set(t) - {"type", "id"} or not isinstance(t.get("type"), str) or "id" in t and not isinstance(t["id"], str) for t in value["targets"]):
            raise ValueError("invalid targets")
        scope = Scope(realm_id, tuple(ScopeTarget(**t) for t in value["targets"]))
        for target in scope.targets:
            scheme = {"CAPABILITY": "capability", "HARNESS": "harness", "TASK": "task", "EXPERIMENT": "experiment"}.get(target.type)
            if scheme:
                validate_id(target.id)
                if not target.id.startswith(scheme + "://"):
                    raise ValueError("scope target identity has a different type")
    except (ValueError, TypeError) as exc:
        raise invalid("invalid delegation target") from exc
    allowed = {"epoch_id", "not_before_us", "expires_at_us", "max_uses", "resource_ceiling", "delegation_depth_remaining"}
    if not isinstance(constraints, dict) or set(constraints) - allowed or type(delegable) is not bool:
        raise invalid("invalid delegation constraints or delegable flag")
    for name in ("not_before_us", "expires_at_us", "max_uses", "delegation_depth_remaining"):
        if name in constraints and (type(constraints[name]) is not int or constraints[name] < 0):
            raise invalid("delegation ceilings/times must be nonnegative integers")
    if "epoch_id" in constraints:
        try:
            validate_id(constraints["epoch_id"])
            if not constraints["epoch_id"].startswith("epoch://"):
                raise ValueError("wrong epoch type")
        except (TypeError, ValueError) as exc:
            raise invalid("invalid constraint epoch") from exc
    if "not_before_us" in constraints and "expires_at_us" in constraints and constraints["not_before_us"] > constraints["expires_at_us"]:
        raise invalid("delegation time interval is inverted")
    if "resource_ceiling" in constraints:
        ceiling = constraints["resource_ceiling"]
        if not isinstance(ceiling, dict) or not all(isinstance(k, str) and k and type(v) is int and v >= 0 for k, v in ceiling.items()):
            raise invalid("invalid resource ceilings")
        if ceiling:
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="public delegation amount-ceiling enforcement is unavailable")
    return subject, frozenset(permissions), scope, GrantConstraints.from_json(constraints), delegable


def revocation_payload(payload):
    if not isinstance(payload, dict) or set(payload) - {"grant_id", "reason_code"}:
        raise invalid("unsupported revocation fields")
    grant_id, reason = payload.get("grant_id"), payload.get("reason_code", "operator_revoke")
    try:
        validate_id(grant_id)
    except (TypeError, ValueError) as exc:
        raise invalid("invalid GrantId") from exc
    if not grant_id.startswith("grant://") or not isinstance(reason, str) or not 1 <= len(reason) <= 128:
        raise invalid("invalid grant revocation identity/reason")
    return grant_id, reason
