"""Root Scratch admission/dispatch; no native work inside the writer.

The public facade uses the same resource grant grouping as Meta calls, so one admitted call
consumes one use per grant even when that grant supplies several permissions.
"""

import json

from ...domain.authority import ScopeTarget
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.scratch_execution import ScratchExecution, ScratchCreate, ScratchRelease, ScratchBindings, ScratchInspect
from ...domain.resource_contract import validate_resource_operation
from .service_certificates import load_service_execution_trust
from . import scratch_journal
from .host_resources import (
    _claim_target,
    _find_grant,
    _service_generation,
    reauthorize,
    read_reservation,
)
from .host_resources import fact


def _fail(code, message):
    raise StableError(code=code, message=message)


def _operation(
    store, txn, task, capability_id, operation, contract="scratch.execute/v1"
):
    try:
        validate_resource_operation(operation)
        if operation.get("resource_contract") != contract:
            raise ValueError("different contract")
    except ValueError:
        _fail(ErrorCode.CONTRACT_INCOMPATIBLE, "invalid Scratch execution declaration")
    current = store.check(task.task_id)
    if (
        current.realm_id,
        current.actor_id,
        current.root_action_id,
        current.serving_composition_id,
    ) != (
        task.realm_id,
        task.actor_id,
        task.root_action_id,
        task.serving_composition_id,
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED, "Scratch Task differs from its Root admission"
        )
    # Read the authoritative frozen surface rather than trusting a caller's
    # operation object or a later global capability surface.
    surface = json.loads(store.read_artifact(current.capability_surface_artifact_id))
    matches = [
        entry
        for entry in surface["operations"]
        if entry["operation_id"] == operation["operation_id"]
    ]
    if len(matches) != 1:
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch operation is outside the frozen surface",
        )
    frozen = matches[0]
    body = json.loads(
        txn._conn.execute(
            "SELECT body_json FROM compositions WHERE realm_id=? AND composition_id=?",
            (task.realm_id, task.serving_composition_id),
        ).fetchone()[0]
    )
    declared = []
    for slot in body.get("slots", {}).values():
        if slot["capability_id"] == capability_id:
            row = txn._conn.execute(
                "SELECT descriptor_json FROM capabilities WHERE capability_id=? AND descriptor_revision=?",
                (capability_id, slot["descriptor_revision"]),
            ).fetchone()
            if row is not None:
                declared.extend(
                    value
                    for value in json.loads(row[0])["operations"]
                    if value["operation_id"] == operation["operation_id"]
                )
    if (
        len(declared) != 1
        or canonical_json(declared[0]) != canonical_json(operation)
        or frozen.get("resource_contract") != contract
        or frozen.get("idempotency") != operation["idempotency"]
        or any(
            set(frozen.get(key, ())) != set(operation[key])
            for key in ("effects", "required_permissions")
        )
        or any(
            frozen.get(direction + "_schema_hash")
            != operation[direction + "_schema_artifact_id"].rsplit("/", 1)[1]
            for direction in ("input", "output")
        )
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch operation differs from the frozen surface",
        )


def admission(store, txn, task, capability_id, operation, request):
    from ...domain.scratch_export_plan import ScratchExportCandidate
    if type(request) is ScratchExportCandidate:
        from .scratch_export import admission as export_admission
        return export_admission(store, txn, task, capability_id, operation, request)
    if type(request) in (ScratchCreate, ScratchRelease, ScratchBindings, ScratchInspect):
        return lifecycle_admission(store, txn, task, capability_id, operation, request)
    if type(request) is not ScratchExecution:
        _fail(
            ErrorCode.INVALID_ARGUMENT,
            "Scratch admission requires its exact typed intent",
        )
    _operation(store, txn, task, capability_id, operation)
    if request.deadline_at_us <= txn.recorded_at_us or (
        task.deadline_at_us is not None and request.deadline_at_us > task.deadline_at_us
    ):
        _fail(
            ErrorCode.DEADLINE_EXCEEDED, "Scratch deadline is outside the Task lifetime"
        )
    # Resolve ownership using the Task's real root Action; the child Invocation
    # is created later in the same writer transaction.
    session, origin = scratch_journal._session(txn, request.session_id)
    epoch = txn._conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id=?", (task.realm_id,)
    ).fetchone()[0]
    if (session[1], origin["composition_id"], origin["epoch_id"]) != (
        task.actor_id,
        task.serving_composition_id,
        epoch,
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch session is outside the admitted execution scope",
        )
    scratch_journal._active(txn, session)
    if request.deadline_at_us > session[6]:
        _fail(
            ErrorCode.DEADLINE_EXCEEDED, "Scratch deadline exceeds its session lifetime"
        )
    source = txn._conn.execute(
        "SELECT kind,media_type,size_bytes,integrity_status FROM artifacts WHERE artifact_id=?",
        (request.source_artifact_id,),
    ).fetchone()
    if source is None or source[3] != "VALID":
        _fail(ErrorCode.INTEGRITY_ERROR, "Scratch Source is not registered and valid")
    if (
        source[1] not in ("text/x-python", "text/plain; charset=utf-8")
        or source[2] > 1024 * 1024
    ):
        _fail(
            ErrorCode.CONTRACT_INCOMPATIBLE,
            "Scratch Source serialization is unavailable",
        )
    if txn._conn.execute(
        "SELECT EXISTS(SELECT 1 FROM artifact_encryption WHERE artifact_id=?) OR "
        "EXISTS(SELECT 1 FROM artifact_blobs WHERE artifact_id=? AND storage_class='ENCRYPTED_RESTRICTED')",
        (request.source_artifact_id, request.source_artifact_id),
    ).fetchone()[0]:
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "restricted Source requires a separate supported access path",
        )
    claims = [
        _claim_target(permission, ScopeTarget("CAPABILITY", capability_id))
        for permission in sorted(
            {"capability.invoke", *operation["required_permissions"]}
        )
    ]
    claims.append(
        _claim_target("capability.invoke", ScopeTarget("ARTIFACT_KIND", source[0]))
    )
    generation = _service_generation(store, task)
    grants = {}
    for subject in (task.actor_id, store.service_id):
        for claim in claims:
            grant = _find_grant(store, txn, task, subject, claim, generation)
            if claim not in grants.setdefault(grant, []):
                grants[grant].append(claim)
    return {
        "schema": "host-resource-reservation/v1",
        "request": request.document(),
        "binding": {
            "session_id": request.session_id,
            "source_kind": source[0],
            "media_type": source[1],
        },
        "operation_sha256": sha256_hex(canonical_json(operation)),
        "grants": grants,
    }


def lifecycle_admission(store, txn, task, capability_id, operation, request):
    _operation(store, txn, task, capability_id, operation, request.document()["schema"])
    binding = {}
    if type(request) in (ScratchRelease, ScratchBindings, ScratchInspect):
        context = scratch_journal._Context(
            "",
            task.root_action_id,
            task.actor_id,
            task.realm_id,
            task.serving_composition_id,
            task.task_id,
            "RUNNING",
            "RUNNING",
            "RUNNING",
            task.deadline_at_us,
        )
        row, _ = scratch_journal._session(txn, request.session_id, context)
        if type(request) is not ScratchRelease:
            scratch_journal._active(txn, row)
        binding = {"session_id": request.session_id, "workspace_id": row[3]}
    claims = [
        _claim_target(permission, ScopeTarget("CAPABILITY", capability_id))
        for permission in sorted(
            {"capability.invoke", *operation["required_permissions"]}
        )
    ]
    generation, grants = _service_generation(store, task), {}
    for subject in (task.actor_id, store.service_id):
        for claim in claims:
            grant = _find_grant(store, txn, task, subject, claim, generation)
            if claim not in grants.setdefault(grant, []):
                grants[grant].append(claim)
    return {
        "schema": "host-resource-reservation/v1",
        "request": request.document(),
        "binding": binding,
        "operation_sha256": sha256_hex(canonical_json(operation)),
        "grants": grants,
    }


def dispatch_lifecycle(
    store, txn, task, invocation_id, request, *, session_id, binding, authorization
):
    reservation = read_reservation(store, invocation_id)
    if reservation["request"] != request.document():
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch lifecycle intent differs from admission",
        )
    context = scratch_journal._context(txn, invocation_id, running=True)
    row, origin = scratch_journal._session(txn, session_id, context)
    if type(request) in (ScratchBindings,ScratchInspect):
        scratch_journal._active(txn,row)
    if type(request) is ScratchCreate and (
        origin["invocation_id"] != invocation_id or row[2] != "STARTING"
    ):
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch creation lifetime differs")
    if type(request) is ScratchRelease and request.session_id != session_id:
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch release lifetime differs")
    scope = {
        "request": request.document(),
        "session_id": session_id,
        "workspace_id": row[3],
    }
    epoch = txn._conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id=?", (task.realm_id,)
    ).fetchone()[0]
    permissions = frozenset(
        claim["permission"]
        for claims in reservation["grants"].values()
        for claim in claims
    )
    expected_effect = "process.spawn" if type(request) is ScratchCreate else "none" if type(request) in (ScratchBindings,ScratchInspect) else "external.irreversible"
    if (
        binding.backend_session_id,
        binding.realm_id,
        binding.epoch_id,
        binding.actor_id,
        binding.action_id,
        binding.effect_kind,
        binding.target_scope_hash,
        dict(binding.resource_ceiling),
        binding.required_permissions,
        binding.deadline_at_us,
    ) != (
        origin["backend_request_id"],
        task.realm_id,
        epoch,
        task.actor_id,
        context.action_id,
        expected_effect,
        sha256_hex(canonical_json(scope)),
        {"calls": 1},
        permissions,
        task.deadline_at_us,
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch lifecycle token differs from Root scope",
        )
    if txn._conn.execute(
        "SELECT 1 FROM facts WHERE entity_id=? AND event_type='scratch_lifecycle_authorized' LIMIT 1",
        (invocation_id,),
    ).fetchone():
        _fail(
            ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
            "Scratch lifecycle submission was already authorized",
        )
    reauthorize(store, txn, task, invocation_id, reservation)
    trust = load_service_execution_trust(
        txn._conn, store.catalog.cas, realm_id=task.realm_id, now_us=txn.recorded_at_us
    )
    if trust.service_principal_id != store.service_id:
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch lifecycle Service differs")
    audit = trust.verifier.verify(
        authorization,
        request_id=invocation_id,
        request_payload_hash=sha256_hex(canonical_json(scope)),
        binding=binding,
        now_us=txn.recorded_at_us,
    )
    fact(
        txn,
        invocation_id,
        "scratch_lifecycle_authorized",
        {
            "schema": "scratch-lifecycle-dispatch/v1",
            **scope,
            "token_id": audit.token_id,
            "token_payload_hash": audit.payload_hash,
            "service_public_key_id": audit.service_public_key_id,
            "certificate_artifact_id": audit.certificate_artifact_id,
        },
    )
    return {}


def dispatch(
    store,
    txn,
    task,
    invocation_id,
    request,
    *,
    worker_session_id,
    binding,
    authorization,
):
    """Commit the only possible submission, using the originally reserved grants."""
    reservation = read_reservation(store, invocation_id)
    if reservation["request"] != request.document():
        _fail(
            ErrorCode.AUTHORITY_DENIED, "Scratch dispatch intent differs from admission"
        )
    row = txn._conn.execute(
        "SELECT i.kind,i.target,i.status,a.task_id,a.actor_id,a.intent,"
        "a.causal_parent_action_id,a.composition_id,t.realm_id FROM invocations i "
        "JOIN actions a ON a.action_id=i.action_id JOIN tasks t ON t.task_id=a.task_id WHERE i.invocation_id=?",
        (invocation_id,),
    ).fetchone()
    if (
        row is None
        or row[0] != "CAPABILITY"
        or row[2:]
        != (
            "RUNNING",
            task.task_id,
            task.actor_id,
            "capability_resource",
            task.root_action_id,
            task.serving_composition_id,
            task.realm_id,
        )
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch dispatch is not its admitted child Invocation",
        )
    epoch = txn._conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id=?", (task.realm_id,)
    ).fetchone()[0]
    _, action = store._journal(txn._conn, invocation_id)
    permissions = frozenset(
        claim["permission"]
        for claims in reservation["grants"].values()
        for claim in claims
    )
    if (
        binding.backend_session_id,
        binding.realm_id,
        binding.epoch_id,
        binding.actor_id,
        binding.action_id,
        binding.effect_kind,
        binding.target_scope_hash,
        dict(binding.resource_ceiling),
        binding.required_permissions,
        binding.deadline_at_us,
    ) != (
        worker_session_id,
        task.realm_id,
        epoch,
        task.actor_id,
        action,
        "external.irreversible",
        sha256_hex(canonical_json(request.document())),
        {"calls": 1, "timeout_us": request.timeout_us},
        permissions,
        request.deadline_at_us,
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch token scope differs from durable admission",
        )
    if txn.recorded_at_us >= request.deadline_at_us:
        _fail(ErrorCode.DEADLINE_EXCEEDED, "Scratch dispatch deadline has expired")
    journal, action = store._journal(txn._conn, invocation_id)
    # Immutable evidence is consulted too: deleting a volatile projection
    # marker cannot turn an accepted submission into a retryable request.
    if (
        "scratch_dispatch" in journal
        or txn._conn.execute(
            "SELECT 1 FROM facts WHERE realm_id=? AND entity_id=? AND event_type='scratch_dispatch_authorized' LIMIT 1",
            (task.realm_id, invocation_id),
        ).fetchone()
    ):
        _fail(
            ErrorCode.EXTERNAL_EFFECT_UNKNOWN,
            "Scratch call has already been authorized for submission",
        )
    reauthorize(store, txn, task, invocation_id, reservation)
    trust = load_service_execution_trust(
        txn._conn, store.catalog.cas, realm_id=task.realm_id, now_us=txn.recorded_at_us
    )
    if trust.service_principal_id != store.service_id:
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch execution Service identity differs")
    audit = trust.verifier.verify(
        authorization,
        request_id=invocation_id,
        request_payload_hash=sha256_hex(canonical_json(request.document())),
        binding=binding,
        now_us=txn.recorded_at_us,
    )
    cell = scratch_journal.record_cell_dispatch(request.session_id, invocation_id)(txn)
    value = {
        "schema": "scratch-dispatch/v1",
        "request": request.document(),
        "worker_session_id": worker_session_id,
        "source_sha256": request.source_artifact_id.rsplit("/", 1)[1],
        "action_id": action,
        "ordinal": cell["ordinal"],
        "token_id": audit.token_id,
        "token_payload_hash": audit.payload_hash,
        "service_public_key_id": audit.service_public_key_id,
        "certificate_artifact_id": audit.certificate_artifact_id,
    }
    journal["scratch_dispatch"] = value
    txn.execute(
        "UPDATE invocations SET backend_ref_json=? WHERE invocation_id=?",
        (canonical_json(journal), invocation_id),
    )
    fact(txn, invocation_id, "scratch_dispatch_authorized", value)
    return value
