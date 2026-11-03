"""Private Root Scratch journal, mutated only inside ``execute_command``.

These mutators record native effects; they do not authorize them. The future
Host must reserve Actor/Service grants and reauthorize immediately before
submitting to an owned worker, outside the writer transaction. A DISPATCHED
receipt is historical evidence, never an execution permit. No native process,
Artifact read, CAS publication or filesystem cleanup happens in this module.

The frozen v1 DDL already has session/binding projections. Cell state lives in
the indexed, immutable Fact chain instead of an unversioned schema alteration.
BEGIN IMMEDIATE serializes the one-live-session/Realm and one-pending-cell
checks. All Scratch writers must use these mutators; the legacy in-process
controller is deliberately not adopted by this journal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ...domain.errors import ErrorCode, StableError
from ...domain.ids import IdError, new_uuid7, parse_uri
from .semantic import _append_edge, _fact

MAX_CELLS = 10_000
MAX_IDLE_US = 30 * 60 * 1_000_000
MAX_WALL_US = 4 * 60 * 60 * 1_000_000
_LIVE = ("STARTING", "ACTIVE", "LOST", "RELEASING", "FAILED")
_CELL_EVENTS = (
    "scratch_cell_reserved",
    "scratch_cell_dispatched",
    "scratch_cell_observed",
)


def _fail(code, message):
    raise StableError(code=code, message=message)


def _id(value, scheme):
    try:
        parse_uri(value, expected=scheme)
    except (IdError, TypeError, AttributeError):
        _fail(ErrorCode.INVALID_ARGUMENT, "invalid Scratch journal identity")
    return value


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(ErrorCode.INVALID_ARGUMENT, "invalid Scratch journal limit")
    return value


@dataclass(frozen=True, slots=True)
class _Context:
    invocation_id: str
    action_id: str
    actor_id: str
    realm_id: str
    composition_id: str
    task_id: str
    task_status: str
    action_status: str
    invocation_status: str
    deadline_at_us: int | None


def _context(txn, invocation_id, *, running=False):
    _id(invocation_id, "invocation")
    row = txn._conn.execute(
        "SELECT i.invocation_id,a.action_id,a.actor_id,t.realm_id,a.composition_id,"
        "t.task_id,t.status,a.status,i.status,t.deadline_at_us,"
        "t.actor_id,t.serving_composition_id FROM invocations i "
        "JOIN actions a ON a.action_id=i.action_id JOIN tasks t ON t.task_id=a.task_id "
        "WHERE i.invocation_id=?",
        (invocation_id,),
    ).fetchone()
    if row is None:
        _fail(ErrorCode.NOT_FOUND, "Scratch Invocation is absent")
    context = _Context(*row[:10])
    if context.realm_id != txn._envelope.realm_id:
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch Invocation belongs to another Realm")
    if context.actor_id != row[10] or context.composition_id != row[11]:
        _fail(ErrorCode.INTEGRITY_ERROR, "Scratch Action differs from its frozen Task")
    if running:
        if (context.task_status, context.action_status, context.invocation_status) != (
            "RUNNING",
            "RUNNING",
            "RUNNING",
        ):
            _fail(
                ErrorCode.FAILED_PRECONDITION, "Scratch activity is no longer running"
            )
        if (
            context.deadline_at_us is not None
            and txn.recorded_at_us >= context.deadline_at_us
        ):
            _fail(ErrorCode.DEADLINE_EXCEEDED, "Scratch Task deadline has expired")
        if txn._conn.execute(
            "SELECT 1 FROM facts WHERE realm_id=? AND entity_id=? "
            "AND event_type='task_cancel_requested' LIMIT 1",
            (context.realm_id, context.task_id),
        ).fetchone():
            _fail(
                ErrorCode.FAILED_PRECONDITION, "Scratch Task cancellation was requested"
            )
    return context


def _event(txn, session_id, context, event, payload):
    return _fact(
        txn,
        entity_type="scratch",
        entity_id=session_id,
        event_type=event,
        actor_id=context.actor_id,
        action_id=context.action_id,
        payload={"schema": "scratch-journal/v1", **payload},
    )


def _origin(txn, session_id):
    row = txn._conn.execute(
        "SELECT payload_json FROM facts WHERE realm_id=? AND entity_type='scratch' "
        "AND entity_id=? AND event_type='scratch_session_reserved' ORDER BY seq LIMIT 1",
        (txn._envelope.realm_id, session_id),
    ).fetchone()
    if row is None:
        _fail(
            ErrorCode.FAILED_PRECONDITION, "session has no Root Scratch journal origin"
        )
    return json.loads(row[0])


def _session(txn, session_id, context=None, *, current_scope=True):
    _id(session_id, "scratch-session")
    row = txn._conn.execute(
        "SELECT realm_id,owner_principal_id,status,workspace_id,backend_request_id,"
        "idle_expires_at_us,wall_expires_at_us FROM scratch_sessions WHERE session_id=?",
        (session_id,),
    ).fetchone()
    if row is None:
        _fail(ErrorCode.NOT_FOUND, "Scratch session is absent")
    if (
        row[0] != txn._envelope.realm_id
        or context is not None
        and row[1] != context.actor_id
    ):
        _fail(ErrorCode.AUTHORITY_DENIED, "Scratch session ownership mismatch")
    origin = _origin(txn, session_id)
    if (
        origin["owner_principal_id"],
        origin["workspace_id"],
        origin["backend_request_id"],
    ) != (row[1], row[3], row[4]):
        _fail(
            ErrorCode.INTEGRITY_ERROR,
            "Scratch session projection differs from its origin",
        )
    epoch = txn._conn.execute(
        "SELECT epoch_id FROM realms WHERE realm_id=?", (row[0],)
    ).fetchone()[0]
    if context is not None and (
        current_scope
        and origin["epoch_id"] != epoch
        or origin["composition_id"] != context.composition_id
    ):
        _fail(
            ErrorCode.AUTHORITY_DENIED,
            "Scratch session is outside the frozen execution scope",
        )
    return row, origin


def _active(txn, row):
    if row[2] != "ACTIVE":
        _fail(ErrorCode.HANDLE_EXPIRED, "Scratch session is not active")
    if txn.recorded_at_us >= min(row[5], row[6]):
        _fail(ErrorCode.HANDLE_EXPIRED, "Scratch session lifetime has expired")


def _artifact(txn, artifact_id):
    _id(artifact_id, "artifact")
    row = txn._conn.execute(
        "SELECT integrity_status FROM artifacts WHERE artifact_id=?", (artifact_id,)
    ).fetchone()
    if row is None or row[0] != "VALID":
        _fail(
            ErrorCode.INTEGRITY_ERROR,
            "Scratch journal Artifact is not registered and valid",
        )


def _cells(txn, session_id):
    # At most MAX_CELLS reservations and two transitions each. This bound is
    # also checked before appending, so reads never walk an unbounded history.
    rows = txn._conn.execute(
        "SELECT event_type,payload_json FROM facts WHERE realm_id=? "
        "AND entity_type='scratch' AND entity_id=? AND event_type IN (?,?,?) "
        "ORDER BY seq LIMIT ?",
        (txn._envelope.realm_id, session_id, *_CELL_EVENTS, MAX_CELLS * 3 + 1),
    ).fetchall()
    if len(rows) > MAX_CELLS * 3:
        _fail(ErrorCode.INTEGRITY_ERROR, "Scratch cell journal exceeds its bound")
    cells = {}
    for event, raw in rows:
        value = json.loads(raw)
        key = value["invocation_id"]
        old = cells.get(key)
        expected = "RESERVED" if event == _CELL_EVENTS[1] else None
        if event == _CELL_EVENTS[0]:
            if old is not None or value["ordinal"] != len(cells) + 1:
                _fail(ErrorCode.INTEGRITY_ERROR, "invalid Scratch reservation order")
        elif (
            old is None
            or (expected is not None and old["status"] != expected)
            or event == _CELL_EVENTS[2]
            and old["status"] not in ("RESERVED", "DISPATCHED")
        ):
            _fail(ErrorCode.INTEGRITY_ERROR, "invalid Scratch cell transition")
        cells[key] = {**(old or {}), **value}
    return cells


def reserve_session(
    invocation_id,
    *,
    workspace_id,
    backend_request_id,
    idle_ttl_us=MAX_IDLE_US,
    wall_ttl_us=MAX_WALL_US,
):
    """Reserve a fresh lifetime; a failed/lost owner blocks reuse until cleanup."""
    _id(workspace_id, "workspace")
    _id(backend_request_id, "invocation")
    _integer(idle_ttl_us, 1, MAX_IDLE_US)
    _integer(wall_ttl_us, idle_ttl_us, MAX_WALL_US)

    def mutate(txn):
        context = _context(txn, invocation_id)
        existing = txn._conn.execute(
            "SELECT session_id FROM scratch_sessions WHERE backend_request_id=?",
            (backend_request_id,),
        ).fetchone()
        if existing:
            row, origin = _session(txn, existing[0], context)
            if (
                origin["invocation_id"],
                row[3],
                origin["idle_ttl_us"],
                origin["wall_ttl_us"],
            ) != (invocation_id, workspace_id, idle_ttl_us, wall_ttl_us):
                _fail(
                    ErrorCode.IDEMPOTENCY_CONFLICT,
                    "Scratch reservation identity was reused",
                )
            return {"session_id": existing[0], "status": row[2]}
        context = _context(txn, invocation_id, running=True)
        # One create Invocation cannot acquire a second lifetime under a new
        # backend request id, even after the first lifetime was released.
        if txn._conn.execute(
            "SELECT 1 FROM facts WHERE realm_id=? AND entity_type='scratch' "
            "AND event_type='scratch_session_reserved' AND action_id=? "
            "AND json_extract(payload_json,'$.invocation_id')=? LIMIT 1",
            (context.realm_id, context.action_id, invocation_id),
        ).fetchone():
            _fail(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                "Scratch create Invocation already has a lifetime",
            )
        if txn._conn.execute(
            "SELECT 1 FROM scratch_sessions WHERE realm_id=? AND status IN (?,?,?,?,?) LIMIT 1",
            (context.realm_id, *_LIVE),
        ).fetchone():
            _fail(ErrorCode.ALREADY_RUNNING, "Realm has an unreleased Scratch lifetime")
        workspace = txn._conn.execute(
            "SELECT realm_id,owner_entity_id,status,expires_at_us FROM workspaces WHERE workspace_id=?",
            (workspace_id,),
        ).fetchone()
        if workspace is None or workspace[:3] != (
            context.realm_id,
            context.action_id,
            "ACTIVE",
        ):
            _fail(
                ErrorCode.AUTHORITY_DENIED,
                "Scratch workspace is not owned by the admitted Action",
            )
        if workspace[3] is not None and workspace[3] < txn.recorded_at_us + wall_ttl_us:
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "Scratch workspace cannot cover the requested lifetime",
            )
        session_id = "scratch-session://" + new_uuid7()
        now = txn.recorded_at_us
        txn.execute(
            "INSERT INTO scratch_sessions VALUES (?,?,?,'STARTING',?,?,?,?,?,?,?)",
            (
                session_id,
                context.realm_id,
                context.actor_id,
                workspace_id,
                backend_request_id,
                now + idle_ttl_us,
                now + wall_ttl_us,
                now,
                now,
                now,
            ),
        )
        epoch = txn._conn.execute(
            "SELECT epoch_id FROM realms WHERE realm_id=?", (context.realm_id,)
        ).fetchone()[0]
        _event(
            txn,
            session_id,
            context,
            "scratch_session_reserved",
            {
                "invocation_id": invocation_id,
                "workspace_id": workspace_id,
                "owner_principal_id": context.actor_id,
                "backend_request_id": backend_request_id,
                "epoch_id": epoch,
                "composition_id": context.composition_id,
                "idle_ttl_us": idle_ttl_us,
                "wall_ttl_us": wall_ttl_us,
            },
        )
        return {"session_id": session_id, "status": "STARTING"}

    return mutate


def _transition(txn, session_id, row, context, status, reason):
    old = row[2]
    if old == status:
        return
    txn.execute(
        "UPDATE scratch_sessions SET status=?,updated_at_us=? WHERE session_id=?",
        (status, txn.recorded_at_us, session_id),
    )
    _event(
        txn,
        session_id,
        context,
        "scratch_session_transitioned",
        {
            "old_status": old,
            "new_status": status,
            "reason_code": reason,
        },
    )


def activate_session(session_id):
    """Confirm readiness already observed outside the writer transaction."""

    def mutate(txn):
        row, origin = _session(txn, session_id)
        context = _context(txn, origin["invocation_id"], running=True)
        _session(txn, session_id, context)
        if row[2] == "ACTIVE":
            _active(txn, row)
            return {"session_id": session_id, "status": "ACTIVE"}
        if row[2] != "STARTING" or txn.recorded_at_us >= min(row[5], row[6]):
            _fail(
                ErrorCode.HANDLE_EXPIRED, "Scratch readiness arrived after its lifetime"
            )
        _transition(txn, session_id, row, context, "ACTIVE", "WORKER_READY")
        return {"session_id": session_id, "status": "ACTIVE"}

    return mutate


def reserve_cell(session_id, invocation_id, *, source_artifact_id, timeout_us):
    _integer(timeout_us, 1, 30_000_000)
    _id(source_artifact_id, "artifact")

    def mutate(txn):
        context = _context(txn, invocation_id)
        row, _ = _session(txn, session_id, context)
        cells = _cells(txn, session_id)
        previous = cells.get(invocation_id)
        if previous:
            if (previous["source_artifact_id"], previous["timeout_us"]) != (
                source_artifact_id,
                timeout_us,
            ):
                _fail(ErrorCode.IDEMPOTENCY_CONFLICT, "Scratch cell request changed")
            return dict(previous)
        _context(txn, invocation_id, running=True)
        _active(txn, row)
        if len(cells) >= MAX_CELLS:
            _fail(ErrorCode.RESOURCE_EXHAUSTED, "Scratch cell lifetime limit reached")
        if any(cell["status"] in ("RESERVED", "DISPATCHED") for cell in cells.values()):
            _fail(
                ErrorCode.ALREADY_RUNNING, "Scratch session already has a pending cell"
            )
        # Prevent an Invocation being rebound to another session, including a
        # terminal lifetime. The action index bounds this lookup to its facts.
        if txn._conn.execute(
            "SELECT 1 FROM facts WHERE realm_id=? AND entity_type='scratch' "
            "AND event_type='scratch_cell_reserved' AND action_id=? "
            "AND json_extract(payload_json,'$.invocation_id')=? LIMIT 1",
            (context.realm_id, context.action_id, invocation_id),
        ).fetchone():
            _fail(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                "Scratch Invocation already belongs to a cell",
            )
        _artifact(txn, source_artifact_id)
        value = {
            "invocation_id": invocation_id,
            "ordinal": len(cells) + 1,
            "source_artifact_id": source_artifact_id,
            "timeout_us": timeout_us,
            "deadline_at_us": min(
                txn.recorded_at_us + timeout_us,
                row[6],
                (
                    context.deadline_at_us
                    if context.deadline_at_us is not None
                    else row[6]
                ),
            ),
            "action_id": context.action_id,
            "status": "RESERVED",
        }
        fact_id = _event(txn, session_id, context, "scratch_cell_reserved", value)
        _append_edge(
            txn,
            fact_id=fact_id,
            edge_type="used",
            from_id=context.action_id,
            to_id=source_artifact_id,
        )
        return value

    return mutate


def record_cell_dispatch(session_id, invocation_id):
    """Record possible submission before touching the worker; never retry it."""

    def mutate(txn):
        context = _context(txn, invocation_id, running=True)
        row, _ = _session(txn, session_id, context)
        _active(txn, row)
        cell = _cells(txn, session_id).get(invocation_id)
        if cell is None:
            _fail(ErrorCode.NOT_FOUND, "Scratch cell reservation is absent")
        if cell["status"] != "RESERVED":
            _fail(
                ErrorCode.FAILED_PRECONDITION, "Scratch cell cannot be dispatched again"
            )
        if txn.recorded_at_us >= cell["deadline_at_us"]:
            _fail(
                ErrorCode.DEADLINE_EXCEEDED,
                "Scratch cell admission deadline has expired",
            )
        _event(
            txn,
            session_id,
            context,
            "scratch_cell_dispatched",
            {
                "invocation_id": invocation_id,
                "status": "DISPATCHED",
            },
        )
        return {**cell, "status": "DISPATCHED"}

    return mutate


def observe_cell(session_id, invocation_id, *, outcome, receipt_artifact_id=None, native_ordinal=None):
    """Record known native outcome independently of output normalization.

    Receipt bytes must be staged/registered by Root in this same transaction
    before calling this mutator. The receipt is a bounded Artifact reference,
    not an unbounded stdout/display payload. UNKNOWN has no invented receipt.
    """
    if outcome not in ("SUCCEEDED", "FAILED", "INTERRUPTED", "UNKNOWN"):
        _fail(ErrorCode.INVALID_ARGUMENT, "invalid Scratch native outcome")
    if (outcome == "UNKNOWN") != (receipt_artifact_id is None):
        _fail(ErrorCode.INVALID_ARGUMENT, "Scratch outcome/receipt mismatch")
    if receipt_artifact_id is not None:
        _id(receipt_artifact_id, "artifact")
    if native_ordinal is not None:
        _integer(native_ordinal, 1, MAX_CELLS)

    def mutate(txn):
        # Terminal Task/deadline must not erase an already observed native
        # effect. Realm/Actor/composition binding remains mandatory.
        context = _context(txn, invocation_id)
        row, _ = _session(txn, session_id, context, current_scope=False)
        cell = _cells(txn, session_id).get(invocation_id)
        if cell is None:
            _fail(ErrorCode.NOT_FOUND, "Scratch cell reservation is absent")
        value = {
            "invocation_id": invocation_id,
            "status": outcome,
            "receipt_artifact_id": receipt_artifact_id,
            **({'native_ordinal':native_ordinal} if native_ordinal is not None else {}),
        }
        if cell["status"] not in ("RESERVED", "DISPATCHED"):
            if (cell["status"], cell.get("receipt_artifact_id")) != (
                outcome,
                receipt_artifact_id,
            ):
                _fail(
                    ErrorCode.IDEMPOTENCY_CONFLICT,
                    "Scratch native outcome is immutable",
                )
            return dict(cell)
        if cell["status"] != "DISPATCHED":
            _fail(ErrorCode.FAILED_PRECONDITION, "Scratch cell was never dispatched")
        if row[2] not in ("ACTIVE", "RELEASING"):
            _fail(
                ErrorCode.HANDLE_EXPIRED,
                "Scratch lifetime cannot accept a native outcome",
            )
        if receipt_artifact_id:
            _artifact(txn, receipt_artifact_id)
        fact_id = _event(txn, session_id, context, "scratch_cell_observed", value)
        if receipt_artifact_id:
            _append_edge(
                txn,
                fact_id=fact_id,
                edge_type="produced",
                from_id=context.action_id,
                to_id=receipt_artifact_id,
            )
        if outcome == "UNKNOWN":
            _lose(txn, session_id, row, context)
        else:
            origin = _origin(txn, session_id)
            txn.execute(
                "UPDATE scratch_sessions SET last_activity_at_us=?,idle_expires_at_us=?,updated_at_us=? WHERE session_id=?",
                (
                    txn.recorded_at_us,
                    min(txn.recorded_at_us + origin["idle_ttl_us"], row[6]),
                    txn.recorded_at_us,
                    session_id,
                ),
            )
        return {**cell, **value}

    return mutate


def abort_cell_reservation(session_id, invocation_id, *, reason_code):
    """A pre-submission denial has no native effect and need not lose the heap."""
    if reason_code not in ErrorCode.ALL:
        _fail(ErrorCode.INVALID_ARGUMENT, "invalid Scratch admission rejection")

    def mutate(txn):
        context = _context(txn, invocation_id)
        _session(txn, session_id, context, current_scope=False)
        cell = _cells(txn, session_id).get(invocation_id)
        if cell is None:
            _fail(ErrorCode.NOT_FOUND, "Scratch cell reservation is absent")
        if cell["status"] == "NOT_DISPATCHED":
            return dict(cell)
        if cell["status"] != "RESERVED":
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "possibly dispatched Scratch cell cannot be aborted as unsent",
            )
        value = {
            "invocation_id": invocation_id,
            "status": "NOT_DISPATCHED",
            "receipt_artifact_id": None,
            "reason_code": reason_code,
        }
        _event(txn, session_id, context, "scratch_cell_observed", value)
        return {**cell, **value}

    return mutate


def _lose(txn, session_id, row, context):
    if row[2] not in ("STARTING", "ACTIVE", "RELEASING", "LOST"):
        _fail(ErrorCode.FAILED_PRECONDITION, "Scratch lifetime cannot be lost")
    _transition(txn, session_id, row, context, "LOST", "WORKER_OWNERSHIP_LOST")
    txn.execute(
        "UPDATE scratch_bindings SET status='EXPIRED' WHERE session_id=? AND status='LIVE'",
        (session_id,),
    )


def lose_session(session_id):
    """Owner recovery: no adoption of a previous kernel and no cell resubmit."""

    def mutate(txn):
        row, origin = _session(txn, session_id)
        context = _context(txn, origin["invocation_id"])
        for cell in _cells(txn, session_id).values():
            if cell["status"] in ("RESERVED", "DISPATCHED"):
                cell_context = _context(txn, cell["invocation_id"])
                # NOT_DISPATCHED is distinguishable from an unknown native
                # effect, but neither may be resubmitted on a lost lifetime.
                status = "NOT_DISPATCHED" if cell["status"] == "RESERVED" else "UNKNOWN"
                _event(
                    txn,
                    session_id,
                    cell_context,
                    "scratch_cell_observed",
                    {
                        "invocation_id": cell["invocation_id"],
                        "status": status,
                        "receipt_artifact_id": None,
                    },
                )
        _lose(txn, session_id, row, context)
        return {"session_id": session_id, "status": "LOST"}

    return mutate


def begin_release(session_id, *, invocation_id=None):
    """Persist cleanup intent; caller must close native owner outside the UoW."""

    def mutate(txn):
        row, origin = _session(txn, session_id)
        context = _context(txn, invocation_id or origin["invocation_id"])
        if invocation_id is not None:
            _session(txn, session_id, context)
        if row[2] == "RELEASED":
            return {
                "session_id": session_id,
                "status": "RELEASED",
                "workspace_id": row[3],
            }
        _transition(txn, session_id, row, context, "RELEASING", "RELEASE_REQUESTED")
        return {"session_id": session_id, "status": "RELEASING", "workspace_id": row[3]}

    return mutate


def confirm_release(session_id):
    """Root confirmation after native shutdown and auditable workspace cleanup.

    The workspace projection must already be RELEASED. This function never
    deletes paths or asserts that a database status proves native shutdown.
    """

    def mutate(txn):
        row, origin = _session(txn, session_id)
        context = _context(txn, origin["invocation_id"])
        if row[2] == "RELEASED":
            return {"session_id": session_id, "status": "RELEASED"}
        if row[2] != "RELEASING":
            _fail(ErrorCode.FAILED_PRECONDITION, "Scratch release was not requested")
        if any(
            c["status"] in ("RESERVED", "DISPATCHED")
            for c in _cells(txn, session_id).values()
        ):
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "Scratch cells need terminal recovery before release",
            )
        workspace = txn._conn.execute(
            "SELECT status FROM workspaces WHERE workspace_id=?", (row[3],)
        ).fetchone()
        if workspace != ("RELEASED",):
            _fail(
                ErrorCode.FAILED_PRECONDITION,
                "Scratch workspace cleanup is not confirmed",
            )
        txn.execute(
            "UPDATE scratch_bindings SET status='RELEASED' WHERE session_id=? AND status IN ('LIVE','EXPIRED','EXPORTED')",
            (session_id,),
        )
        _transition(
            txn, session_id, row, context, "RELEASED", "OWNER_AND_WORKSPACE_RELEASED"
        )
        return {"session_id": session_id, "status": "RELEASED"}

    return mutate
