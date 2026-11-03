"""Immutable admission View preimage, staged before the accepting transaction.

This is a bounded execution View, not the mutable administrative RuntimeView.
Its expected meta revision is the revision of the Task acceptance itself.
"""

import json

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from .state import current_state_bindings


def acceptance_view(conn, *, realm_id, actor_id, composition_id, serving_revision,
                    surface_artifact_id, authority_fingerprint, backend_profile_hash,
                    context_profile_artifact_id=None, causal_parent_action_id=None, now_us=None, pending_use=None):
    realm = conn.execute("SELECT epoch_id,current_meta_revision FROM realms WHERE realm_id=?", (realm_id,)).fetchone()
    refs = conn.execute("SELECT serving_revision FROM composition_refs WHERE realm_id=?", (realm_id,)).fetchone()
    composition = conn.execute("SELECT body_json,revision FROM compositions WHERE composition_id=? AND realm_id=?", (composition_id, realm_id)).fetchone()
    if realm is None or refs is None or refs[0] != serving_revision or composition is None or composition[1] != serving_revision:
        raise StableError(code=ErrorCode.REVISION_CONFLICT, message="serving snapshot changed before admission")
    body = json.loads(composition[0])
    owners = {composition_id, *(slot["capability_id"] for slot in body.get("slots", {}).values())}
    states = current_state_bindings(conn, realm_id, owners=owners, active_only=True)
    packages = conn.execute(
        "SELECT DISTINCT h.manifest_artifact_id,h.package_artifact_id,h.harness_id FROM harness_installations h "
        "JOIN harness_installation_history x ON x.harness_id=h.harness_id WHERE x.composition_id=? AND h.realm_id=? AND h.status!='UNINSTALLED'",
        (composition_id, realm_id)).fetchall()
    if len(packages) > 1:
        raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="Task composition has ambiguous package ownership")
    value = {"schema": "task-acceptance-view/v1", "realm_id": realm_id, "epoch_id": realm[0],
        "actor_id": actor_id, "meta_revision": realm[1] + 1, "composition_id": composition_id,
        "composition": body, "serving_revision": serving_revision, "state_snapshot": states,
        "capability_surface_artifact_id": surface_artifact_id, "authority_fingerprint": authority_fingerprint,
        "backend_profile_hash": backend_profile_hash,
        "harness_manifest_artifact_id": packages[0][0] if packages else None,
        "package_artifact_id": packages[0][1] if packages else None}
    if states:
        value['state_cas_snapshot'] = {state_id: conn.execute(
            'SELECT cas_revision FROM managed_states WHERE state_id=?', (state_id,)).fetchone()[0]
            for state_id in sorted(states)}
    if len(packages)==1:
        from .provider_configuration import provider_configuration
        provider=provider_configuration(conn,realm_id,packages[0][2])
        if provider is not None:
            value['provider_configuration_fact_id']=provider['configuration_fact_id']
    if context_profile_artifact_id is not None:
        from .context_snapshot import capture_context_sources
        if len(packages) != 1 or now_us is None:
            raise StableError(code=ErrorCode.REVISION_CONFLICT, message="Context package ownership changed before admission")
        value["context_profile_artifact_id"] = context_profile_artifact_id
        value["context_sources"] = capture_context_sources(conn, realm_id=realm_id, actor_id=actor_id, epoch_id=realm[0],
            composition_id=composition_id, serving_revision=serving_revision, states=states, now_us=now_us,
            causal_parent_action_id=causal_parent_action_id, pending_use=pending_use)
    content = canonical_json(value)
    return {"content": content, "artifact_id": "artifact://sha256/" + sha256_hex(content), "value": value}


def register_staged_artifact(txn, staged, *, kind="host_record", parents=(), media_type="application/json"):
    txn._conn.execute(
        "INSERT OR IGNORE INTO artifacts(artifact_id,kind,media_type,size_bytes,schema_version,created_by,created_at_us,parents_json,manifest_json,integrity_status) VALUES (?,?,?,?,1,?,?,?,?, 'VALID')",
        (staged["artifact_id"], kind, media_type, len(staged["content"]), txn._envelope.actor_id, txn.recorded_at_us, canonical_json(list(parents)), canonical_json(staged["manifest"])))
