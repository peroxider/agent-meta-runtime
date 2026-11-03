"""Root-derived binding provenance and weak-handle admission, never heap storage."""

import json

from ...domain.canonical import canonical_json, sha256_hex
from ...domain.errors import ErrorCode, StableError
from . import scratch_journal
from .host_resources import fact
from .semantic import _append_edge


def _fail(message):
    raise StableError(code=ErrorCode.INTEGRITY_ERROR, message=message)


def cell_index(store, session_id):
    rows = store.conn.execute(
        "SELECT event_type,payload_json FROM facts WHERE realm_id=? AND entity_type='scratch' "
        "AND entity_id=? AND event_type IN ('scratch_cell_reserved','scratch_cell_observed') ORDER BY seq LIMIT 20001",
        (store.realm_id, session_id),
    ).fetchall()
    if len(rows) > 20000:
        _fail("Scratch cell provenance exceeds its lifetime bound")
    reserved, index = {}, {}
    for event, raw in rows:
        value = json.loads(raw)
        if event == "scratch_cell_reserved":
            reserved[value["invocation_id"]] = value
        elif value.get("receipt_artifact_id") is not None:
            cell = reserved.get(value["invocation_id"])
            if cell is None:
                _fail("Scratch observation has no admitted cell")
            native = value.get("native_ordinal")
            if native is None:
                receipt = json.loads(store.read_artifact(value["receipt_artifact_id"]))
                if (
                    receipt.get("source_artifact_id") != cell["source_artifact_id"]
                    or receipt.get("session_id") != session_id
                ):
                    _fail("Scratch legacy native receipt differs from admission")
                native = receipt["worker_ordinal"]
            if type(native) is not int or not 1 <= native <= 10000 or native in index:
                _fail("Scratch native ordinal is ambiguous")
            index[native] = {
                "cell_ordinal": cell["ordinal"],
                "source_artifact_id": cell["source_artifact_id"],
                "action_id": cell["action_id"],
                "invocation_id": cell["invocation_id"],
            }
    return index


def inventory(store, task, session_id, snapshot):
    """Build immutable public metadata outside a writer; Root supplies origins."""
    index = cell_index(store, session_id)
    native = snapshot["cell_ordinal"]
    if type(native) is not int or native < 0 or native and native not in index:
        _fail("Scratch binding snapshot has no confirmed native cell")
    entries, redacted = [], False
    for item in snapshot["bindings"]:
        created, changed = item.get("created_cell"), item.get("last_changed_cell")
        # Fixed bootstrap namespace is not an authorized user Source origin.
        if created in (None, 0) or changed in (None, 0):
            continue
        if (
            created not in index
            or changed not in index
            or not created <= changed <= native
        ):
            _fail("Scratch binding cell origin is unavailable")
        if (
            type(item.get("binding_generation")) is not int
            or item["binding_generation"] < 1
        ):
            _fail("Scratch binding generation is invalid")
        source, last = index[created], index[changed]
        value = {
            **item,
            "created_cell": source["cell_ordinal"],
            "last_changed_cell": last["cell_ordinal"],
            "created_source_artifact_id": source["source_artifact_id"],
            "source_artifact_id": last["source_artifact_id"],
            "created_by_action_id": source["action_id"],
            "last_cell_action_id": last["action_id"],
            "created_by_invocation_id": source["invocation_id"],
            "last_changed_invocation_id": last["invocation_id"],
            "binding_write_tracking_complete": snapshot[
                "binding_write_tracking_complete"
            ],
            "binding_write_tracking_scope": snapshot["binding_write_tracking_scope"],
            "value_mutation_impact": "UNKNOWN_RISK",
        }
        safe = store.resource_value(task, value)
        if safe["name"] != value["name"]:
            redacted = True
            continue
        safe["type_metadata_redacted"] = any(
            safe[key] != value[key] for key in ("type_name", "type_module")
        )
        entries.append(safe)
    return {
        "schema": "scratch-bindings-receipt/v1",
        "session_id": session_id,
        "cell_ordinal": index[native]["cell_ordinal"] if native else 0,
        "bindings": entries,
        "truncated": snapshot["truncated"] or redacted,
        "bindings_redacted": redacted,
        "binding_write_tracking_complete": snapshot["binding_write_tracking_complete"],
        "binding_write_tracking_scope": snapshot["binding_write_tracking_scope"],
        "value_mutation_impact": "UNKNOWN_RISK",
    }


def persist_snapshot(store, txn, task, invocation_id, value):
    context = scratch_journal._context(txn, invocation_id)
    row, _ = scratch_journal._session(txn, value["session_id"], context)
    scratch_journal._active(txn, row)
    source = fact(txn, invocation_id, "scratch_bindings_observed", value)
    if not value["truncated"]:
        txn.execute(
            "UPDATE scratch_bindings SET status='EXPIRED' WHERE session_id=? AND status='LIVE' AND binding_name NOT LIKE '@handle:%'",
            (value["session_id"],),
        )
    for item in value["bindings"]:
        handle_hash = (
            sha256_hex(item["handle"].encode()) if item.get("handle") else None
        )
        # A newer generation invalidates earlier binding-name projections;
        # any independently issued weak handle still resolves only via kernel.
        txn.execute(
            "UPDATE scratch_bindings SET status='EXPIRED' WHERE session_id=? AND binding_name=? AND generation!=? AND status='LIVE'",
            (value["session_id"], item["name"], item["binding_generation"]),
        )
        txn.execute(
            "INSERT INTO scratch_bindings VALUES (?,?,?,?,?,?,?,?,'LIVE',?) "
            "ON CONFLICT(session_id,binding_name,generation) DO UPDATE SET status='LIVE',metadata_json=excluded.metadata_json,observed_handle_hash=excluded.observed_handle_hash,"
            "type_module=excluded.type_module,type_name=excluded.type_name,source_artifact_id=excluded.source_artifact_id,last_cell_action_id=excluded.last_cell_action_id",
            (
                value["session_id"],
                item["name"],
                item["binding_generation"],
                item["type_module"],
                item["type_name"],
                item["source_artifact_id"],
                item["last_cell_action_id"],
                handle_hash,
                canonical_json(item),
            ),
        )
        if handle_hash is not None:
            persist_handles(txn, value["session_id"], item, [handle_hash])
        _append_edge(
            txn,
            fact_id=source,
            edge_type="used",
            from_id=context.action_id,
            to_id=item["source_artifact_id"],
        )


def target(store, session_id, request):
    """Name/handle must come from Root-observed metadata in this exact session."""
    if request.name is not None:
        row = store.conn.execute(
            "SELECT metadata_json FROM scratch_bindings WHERE session_id=? AND binding_name=? "
            "AND status='LIVE' ORDER BY generation DESC LIMIT 1",
            (session_id, request.name),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="Scratch binding has no live Source provenance",
            )
        return json.loads(row[0])
    digest = sha256_hex(request.handle.encode())
    row = store.conn.execute(
        "SELECT metadata_json FROM scratch_bindings WHERE session_id=? AND binding_name=? AND generation=1 AND status='LIVE'",
        (session_id, "@handle:" + digest),
    ).fetchone()
    if row is not None:
        return json.loads(row[0])
    raise StableError(
        code=ErrorCode.HANDLE_EXPIRED,
        message="Scratch handle was not issued in this session",
    )


def persist_handles(txn, session_id, origin, hashes):
    for digest in hashes:
        txn.execute(
            "INSERT INTO scratch_bindings VALUES (?,?,1,?,?,?,?,?,'LIVE',?) "
            "ON CONFLICT(session_id,binding_name,generation) DO UPDATE SET status='LIVE',metadata_json=excluded.metadata_json,"
            "type_module=excluded.type_module,type_name=excluded.type_name,source_artifact_id=excluded.source_artifact_id,last_cell_action_id=excluded.last_cell_action_id",
            (
                session_id,
                "@handle:" + digest,
                origin["type_module"],
                origin["type_name"],
                origin["source_artifact_id"],
                origin["last_cell_action_id"],
                digest,
                canonical_json(origin),
            ),
        )
    # Bound the live capability index independently of an unbounded Fact
    # history. Eviction expires an observation; it never retains a value.
    txn.execute(
        "UPDATE scratch_bindings SET status='EXPIRED' WHERE rowid IN (SELECT rowid FROM scratch_bindings "
        "WHERE session_id=? AND binding_name LIKE '@handle:%' AND status='LIVE' ORDER BY rowid DESC LIMIT -1 OFFSET 4096)",
        (session_id,),
    )


def issued_handles(node):
    found, pending = set(), [node]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            token = item.get("handle")
            if type(token) is str and token.startswith("obs:"):
                found.add(sha256_hex(token.encode()))
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return sorted(found)
