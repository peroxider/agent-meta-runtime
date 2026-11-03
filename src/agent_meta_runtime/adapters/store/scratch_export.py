"""Root-authorized Source retrieval and atomic candidate publication."""

import asyncio
import json

from ...domain.authority import ScopeTarget
from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from ...domain.harness import is_artifact_id
from ...domain.scratch_export import ExportArtifact, ScratchSource, build_scratch_export
from ...domain.resource_contract import ResourceReceipt
from . import scratch_journal
from .scratch_bindings import cell_index
from .host_resources import (
    _claim_target,
    _find_grant,
    _service_generation,
    reauthorize,
    read_reservation,
    fact,
)
from .semantic import _append_edge
from .task_snapshot import register_staged_artifact

MAX_INPUT_BYTES = 72 * 1024 * 1024


def _fail(code, message):
    raise StableError(code=code, message=message)


def _metadata(store, reference):
    row = store.conn.execute(
        "SELECT kind,media_type,size_bytes,integrity_status FROM artifacts WHERE artifact_id=?",
        (reference,),
    ).fetchone()
    if row is None or row[3] != "VALID":
        _fail(
            ErrorCode.INTEGRITY_ERROR,
            "Scratch export input is not registered and valid",
        )
    if store.conn.execute(
        "SELECT EXISTS(SELECT 1 FROM artifact_encryption WHERE artifact_id=?) OR "
        "EXISTS(SELECT 1 FROM artifact_blobs WHERE artifact_id=? AND storage_class='ENCRYPTED_RESTRICTED')",
        (reference, reference),
    ).fetchone()[0]:
        _fail(
            ErrorCode.AUTHORITY_DENIED, "Scratch export cannot read restricted inputs"
        )
    return row


def _session(txn, request, context):
    row, origin = scratch_journal._session(txn, request.session_id, context)
    scratch_journal._active(txn, row)
    return row, origin


def admission(store, txn, task, capability_id, operation, request):
    from .scratch_admission import _operation

    _operation(store, txn, task, capability_id, operation, "scratch.export/v1")
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
    _session(txn, request, context)
    claims = [
        _claim_target(permission, ScopeTarget("CAPABILITY", capability_id))
        for permission in sorted(
            {"capability.invoke", *operation["required_permissions"]}
        )
    ]
    total, metadata = 0, {}
    for reference in request.inputs():
        row = _metadata(store, reference)
        ceiling = (
            32 * 1024 * 1024
            if reference in request.dependency_artifact_ids
            else 1024 * 1024
        )
        if row[2] > ceiling:
            _fail(
                ErrorCode.RESOURCE_EXHAUSTED,
                "Scratch export input exceeds its size ceiling",
            )
        total += row[2]
        metadata[reference] = list(row[:3])
        claim = _claim_target("capability.invoke", ScopeTarget("ARTIFACT_KIND", row[0]))
        if claim not in claims:
            claims.append(claim)
    if total > MAX_INPUT_BYTES:
        _fail(
            ErrorCode.RESOURCE_EXHAUSTED,
            "Scratch export input closure exceeds its size ceiling",
        )
    generation, grants = _service_generation(store, task), {}
    for subject in (task.actor_id, store.service_id):
        for claim in claims:
            grant = _find_grant(store, txn, task, subject, claim, generation)
            if claim not in grants.setdefault(grant, []):
                grants[grant].append(claim)
    return {
        "schema": "host-resource-reservation/v1",
        "request": request.document(),
        "binding": {"session_id": request.session_id, "inputs": metadata},
        "operation_sha256": sha256_hex(canonical_json(operation)),
        "grants": grants,
    }


def _references(value):
    found = set()
    pending = [value]
    scanned = 0
    while pending:
        item = pending.pop()
        scanned += 1
        if scanned > 50000:
            _fail(
                ErrorCode.RESOURCE_EXHAUSTED,
                "Scratch export contract exceeds its complexity ceiling",
            )
        if type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif is_artifact_id(item):
            found.add(item)
    return found


async def prepare(store, task, invocation_id, request):
    reservation = read_reservation(store, invocation_id)

    def authorized(txn):
        reauthorize(store, txn, task, invocation_id, reservation)
        _session(
            txn, request, scratch_journal._context(txn, invocation_id, running=True)
        )
        return {}

    store.run_command(authorized)
    # The immutable journal establishes Source membership; no live binding,
    # kernel evaluation or Source supplied by another session is accepted.
    index = cell_index(store, request.session_id)
    occurrences = {reference: [] for reference in request.source_artifact_ids}
    for cell in index.values():
        if cell["source_artifact_id"] in occurrences:
            occurrences[cell["source_artifact_id"]].append(cell)
    origins = [
        {**cells[-1], "confirmed_cell_count": len(cells)}
        for cells in occurrences.values()
        if cells
    ]
    if {cell["source_artifact_id"] for cell in origins} != set(
        request.source_artifact_ids
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch export Source is not a confirmed cell of this session",
        )
    raw = {}
    for reference, expected in reservation["binding"]["inputs"].items():
        if list(_metadata(store, reference)[:3]) != expected:
            _fail(ErrorCode.INTEGRITY_ERROR, "Scratch export input metadata changed")
        content = store.read_artifact(reference)
        if (
            len(content) != expected[2]
            or "artifact://sha256/" + sha256_hex(content) != reference
        ):
            _fail(
                ErrorCode.INTEGRITY_ERROR,
                "Scratch export input differs from its identity",
            )
        raw[reference] = content
    try:
        # Preserve transitive JSON references too: schema/state documents may
        # reference other immutable schemas. Cycles are visited only once.
        support, scanned, pending = set(), set(), [request.contract_artifact_id]
        while pending:
            reference = pending.pop()
            if reference in scanned:
                continue
            scanned.add(reference)
            if reference not in raw:
                _fail(
                    ErrorCode.CONTRACT_INCOMPATIBLE,
                    "Scratch export contract closure is incomplete",
                )
            if reservation["binding"]["inputs"][reference][1] == "application/json":
                for nested in _references(json.loads(raw[reference])):
                    if nested != request.contract_artifact_id:
                        support.add(nested)
                    if nested not in scanned:
                        pending.append(nested)
        if support != set(request.support_artifact_ids):
            _fail(
                ErrorCode.CONTRACT_INCOMPATIBLE,
                "Scratch export requires the exact contract Artifact closure",
            )
        sources = tuple(
            ScratchSource(reference, raw[reference])
            for reference in request.source_artifact_ids
        )
        contract = ExportArtifact(
            request.contract_artifact_id, raw[request.contract_artifact_id]
        )
        lock = ExportArtifact(
            request.dependency_lock_artifact_id,
            raw[request.dependency_lock_artifact_id],
        )
        dependencies = tuple(
            ExportArtifact(reference, raw[reference])
            for reference in request.dependency_artifact_ids
        )
        # Candidate text/document inputs cannot silently change under policy:
        # redacting generated source would destroy its canonical identity.
        for reference in (
            *request.source_artifact_ids,
            request.contract_artifact_id,
            request.dependency_lock_artifact_id,
        ):
            text = raw[reference].decode("utf-8")
            value = (
                json.loads(text)
                if reference not in request.source_artifact_ids
                else text
            )
            if store.resource_value(task, value) != value:
                _fail(
                    ErrorCode.AUTHORITY_DENIED,
                    "Scratch export input requires policy redaction",
                )
        result = await asyncio.to_thread(
            build_scratch_export,
            sources=sources,
            export_names=request.export_names,
            contract=contract,
            dependency_lock=lock,
            entrypoint=request.entrypoint,
            dependency_artifacts=dependencies,
            name=request.name,
            version=request.version,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail(ErrorCode.INVALID_ARGUMENT, "Scratch export inputs are invalid")
    value = {
        "schema": "scratch-export-receipt/v1",
        "session_id": request.session_id,
        "package_artifact_id": result.package.artifact_id,
        "provenance_artifact_id": result.provenance.artifact_id,
        "input_artifact_ids": list(request.inputs()),
        "source_cells": origins,
        "source_origin_selection": "LATEST_CONFIRMED_OCCURRENCE_PER_SOURCE",
        "trust_class": "trusted_candidate",
        "entrypoint": request.entrypoint,
        "exported_by_action_id": store._journal(store.conn, invocation_id)[1],
        "serving_changed": False,
        "experiment_promotion_required": True,
    }
    safe = store.resource_value(task, value)
    if safe != value:
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch export receipt requires identity redaction",
        )
    staged = store.stage(canonical_json(value))
    staged["scratch_export"] = {
        "package": store.stage(result.package.content),
        "provenance": store.stage(result.provenance.content),
        "receipt": value,
    }
    return (
        ResourceReceipt(
            "scratch.export/v1",
            staged["artifact_id"],
            "application/json",
            staged["content"],
        ),
        staged,
    )


def commit(store, txn, task, invocation_id, request, staged):
    _session(txn, request, scratch_journal._context(txn, invocation_id, running=True))
    export = staged["scratch_export"]
    inputs = request.inputs()
    for reference, expected in read_reservation(store, invocation_id)["binding"][
        "inputs"
    ].items():
        if list(_metadata(store, reference)[:3]) != expected:
            _fail(
                ErrorCode.INTEGRITY_ERROR,
                "Scratch export input metadata changed before publication",
            )
    for key, kind, media in (
        ("package", "capability_package", "application/vnd.agent-meta.ampak"),
        ("provenance", "build_provenance", "application/json"),
    ):
        content = export[key]
        current = txn._conn.execute(
            "SELECT media_type,size_bytes FROM artifacts WHERE artifact_id=?",
            (content["artifact_id"],),
        ).fetchone()
        if current is not None and current != (media, len(content["content"])):
            _fail(
                ErrorCode.CONTRACT_INCOMPATIBLE,
                "Existing candidate Artifact metadata differs",
            )
        register_staged_artifact(
            txn, content, kind=kind, media_type=media, parents=inputs
        )
    source = fact(
        txn,
        invocation_id,
        "scratch_candidate_exported",
        {
            **export["receipt"],
            "redaction_profile_artifact_id": task.context.profile_artifact_id,
        },
    )
    for reference in inputs:
        _append_edge(
            txn,
            fact_id=source,
            edge_type="used",
            from_id=export["receipt"]["exported_by_action_id"],
            to_id=reference,
        )
    produced = [export[key]["artifact_id"] for key in ("package", "provenance")]
    for reference in produced:
        _append_edge(
            txn,
            fact_id=source,
            edge_type="produced",
            from_id=invocation_id,
            to_id=reference,
        )
    return produced
