"""Revalidate an admitted Provider attempt before its only worker submission."""

import json

from ...domain.authority import ScopeTarget, authorize
from ...domain.canonical import canonical_json
from ...domain.errors import ErrorCode, StableError
from ...domain.provider_transport import authorize_provider_request
from .authority import load_grant_row
from .provider_accounting import accounting_fact, read_provider
from .provider_admission import authorize_configuration
from ...domain.provider_accounting import ProviderReservation
from .service_certificates import load_service_execution_trust


def authorize_dispatch(store, txn, task, invocation_id, request, binding, authorization):
    current = store.check(task.task_id)
    row = txn._conn.execute("SELECT action_id,kind,target,status,backend_ref_json FROM invocations WHERE invocation_id=?", (invocation_id,)).fetchone()
    if row is None or row[:2] != (current.root_action_id, "MODEL") or row[3] != "RUNNING":
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Provider attempt is not admitted and running")
    journal = json.loads(row[4])
    provider = read_provider(txn._conn, invocation_id, journal)
    epoch = txn._conn.execute("SELECT epoch_id FROM realms WHERE realm_id=?", (store.realm_id,)).fetchone()[0]
    if (provider is None or provider["settlement"] is not None or request.request_id != journal["request_id"]
            or request.scope_hash != provider["reservation"]["request_hash"]
            or request.required_ceiling["output_tokens"] != provider["reservation"]["maximum_output_tokens"]
            or (binding.realm_id, binding.epoch_id, binding.actor_id, binding.action_id) !=
               (current.realm_id, epoch, current.actor_id, current.root_action_id)
            or binding.deadline_at_us != request.deadline_at_us or request.deadline_at_us is None
            or request.deadline_at_us <= txn.recorded_at_us
            or current.deadline_at_us is not None and request.deadline_at_us > current.deadline_at_us):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider dispatch differs from durable admission")
    if "provider_dispatch" in journal:
        raise StableError(code=ErrorCode.EXTERNAL_EFFECT_UNKNOWN, message="Provider attempt already authorized for submission")
    capability = row[2].split("#", 1)[0]
    document = provider['reservation']
    if document.get('configuration_fact_id') is not None:
        authorize_configuration(store,task,capability,ProviderReservation(**{key:value for key,value in document.items() if key!='schema'}),request)
    permissions = {current.actor_id: set(), store.service_id: set()}
    uses = txn._conn.execute("SELECT grant_id,amount_json FROM authority_uses WHERE action_id=? AND use_kind='host_invocation'", (invocation_id,)).fetchall()
    for grant_id, raw in uses:
        grant = load_grant_row(txn._conn, grant_id)
        if grant is None or grant.subject_id not in permissions or grant.constraints.resource_ceiling:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider admission grant is unavailable")
        principal = txn._conn.execute("SELECT status FROM principals WHERE realm_id=? AND principal_id=?", (store.realm_id, grant.subject_id)).fetchone()
        if principal != ("ACTIVE",):
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider principal is inactive")
        reserved = json.loads(raw)
        if set(reserved) != {"permissions"} or not reserved["permissions"]:
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Provider admission grant use is invalid")
        count = txn._conn.execute("SELECT COUNT(*) FROM authority_uses WHERE grant_id=?", (grant_id,)).fetchone()[0]
        for permission in reserved["permissions"]:
            # This attempt already owns its reserved use. Recheck the same
            # grant, excluding that use, rather than borrowing a new grant.
            if authorize(grant, subject_id=grant.subject_id, permission=permission, resource_realm=store.realm_id,
                    resource_target=ScopeTarget("CAPABILITY", capability), epoch_id=epoch,
                    now_us=txn.recorded_at_us, uses_count=count-1) is not None:
                raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider admission grant no longer authorizes dispatch")
            permissions[grant.subject_id].add(permission)
    if any(value != set(binding.required_permissions) for value in permissions.values()):
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider dispatch permissions differ from admission")
    trust = load_service_execution_trust(txn._conn, store.catalog.cas, realm_id=store.realm_id, now_us=txn.recorded_at_us)
    if trust.service_principal_id != store.service_id:
        raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="Provider dispatch Service identity differs")
    audit, _, _ = authorize_provider_request(trust.verifier, request, authorization=authorization,
        binding=binding, now_us=txn.recorded_at_us)
    dispatch = {"schema": "provider-dispatch/v1", "request_id": request.request_id,
        "request_scope_hash": request.scope_hash, "worker_session_id": binding.backend_session_id,
        "token_id": audit.token_id, "token_payload_hash": audit.payload_hash,
        "service_public_key_id": audit.service_public_key_id,
        "certificate_artifact_id": audit.certificate_artifact_id}
    journal["provider_dispatch"] = dispatch
    txn._conn.execute("UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?", (canonical_json(journal), invocation_id))
    accounting_fact(txn, invocation_id, "provider_dispatch_authorized", dispatch)
    return dispatch
