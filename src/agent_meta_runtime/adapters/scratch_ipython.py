"""IPython Scratch adapter (§41.54).

Host-owned interactive worker: a single ipykernel-backed session per realm
with deny-by-default magics, bounded output streams, TTL expiry and no
kernel-heap restore after a restart. Bindings observed in the kernel
namespace are recorded in ``scratch_sessions``/``scratch_bindings``;
``export_candidate`` re-derives a ``capability-package/v1`` candidate from
the cell source by AST analysis and fails closed with ``OPAQUE_DEPENDENCY``
when the selection reads free variables the package cannot carry.
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import io
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.reflection import InspectBudget, SafeReflector

__all__ = [
    "ALLOWED_MAGICS",
    "IDLE_TTL_US",
    "OUTPUT_LIMIT_BYTES",
    "WALL_TTL_US",
    "BindingRecord",
    "InProcessIpykernel",
    "KernelWorker",
    "ScratchSessionController",
    "check_cell_source",
    "execute_config",
    "truncate_stream",
]

#: §41.54: idle TTL 30 min, wall TTL 4 h, output streams capped at 1 MiB.
IDLE_TTL_US = 30 * 60 * 1_000_000
WALL_TTL_US = 4 * 3600 * 1_000_000
OUTPUT_LIMIT_BYTES = 1024 * 1024

#: Line magics explicitly allowed; every other magic (and every cell magic)
#: is denied by default.
ALLOWED_MAGICS = frozenset({"%time", "%timeit", "%whos"})

#: IPython input-transformer escapes denied before reaching the kernel.
_ESCAPE_PREFIXES = ("!", "!!", "?", "/", ";", ",")

_STATUS_ACTIVE = ("STARTING", "ACTIVE")
_NAMESPACE_IGNORABLE = frozenset({"In", "Out", "get_ipython", "exit", "quit", "open"})


def check_cell_source(source: str) -> tuple[str, ...]:
    """Static cell gate; returns sorted issue strings (deny-by-default)."""

    issues: list[str] = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if not stripped:
            continue
        for prefix in _ESCAPE_PREFIXES:
            if stripped.startswith(prefix):
                issues.append("scratch.escape:" + prefix)
                break
        else:
            if stripped.startswith("%"):
                magic = stripped.split(" ", 1)[0]
                if magic not in ALLOWED_MAGICS:
                    issues.append("scratch.magic:" + magic)
                if magic.startswith("%%"):
                    issues.append("scratch.cell_magic:" + magic)
    return tuple(sorted(set(issues)))


def execute_config(timeout_s: float = 30.0) -> dict[str, Any]:
    """Normalized run options for the scratch worker (§41.54)."""

    return {"timeout_s": timeout_s, "store_history": False, "silent": False}


def truncate_stream(text: str, limit: int = OUTPUT_LIMIT_BYTES) -> tuple[str, bool]:
    """Cap one captured stream at ``limit`` bytes (UTF-8 boundary safe)."""

    blob = text.encode("utf-8")
    if len(blob) <= limit:
        return text, False
    cut = blob[:limit].decode("utf-8", errors="ignore")
    return cut + "\n...[truncated]", True


@dataclass(frozen=True, slots=True)
class BindingRecord:
    """One observed namespace binding (row of ``scratch_bindings``)."""

    session_id: str
    binding_name: str
    generation: int
    type_module: str
    type_name: str
    source_artifact_id: str
    last_cell_action_id: str
    observed_handle_hash: str | None
    status: str
    metadata_json: bytes


class KernelWorker(Protocol):
    """The single execution surface the controller drives."""

    def run_cell(self, source: str) -> dict[str, Any]: ...

    def namespace(self) -> Mapping[str, Any]: ...

    def shutdown(self) -> None: ...


def _sanitize_exception(exc: BaseException) -> dict[str, Any]:
    reflector = SafeReflector()
    node = reflector.reflect(exc, InspectBudget(max_depth=2))
    return {
        "type_name": node.type_name or type(exc).__name__,
        "reason_hash": node.reason_hash,
    }


class InProcessIpykernel:
    """In-process ipykernel worker; never restores kernel heap state."""

    def __init__(self) -> None:
        try:
            from ipykernel.inprocess.ipkernel import InProcessKernel
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise StableError(
                code=ErrorCode.FEATURE_UNAVAILABLE,
                message="ipykernel is not installed; scratch is unavailable",
            ) from exc
        self._kernel = InProcessKernel()
        shell = self._kernel.shell
        shell.history_manager.enabled = False  # type: ignore[union-attr]
        shell.cache_size = 0
        self._reflector = SafeReflector()

    def run_cell(self, source: str) -> dict[str, Any]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self._kernel.shell.run_cell(  # type: ignore[union-attr]
                source,
                store_history=execute_config()["store_history"],
                silent=execute_config()["silent"],
            )
        stdout, stdout_cut = truncate_stream(out.getvalue())
        stderr, stderr_cut = truncate_stream(err.getvalue())
        errors: list[dict[str, Any]] = []
        for exc in (result.error_before_exec, result.error_in_exec):
            if exc is not None:
                errors.append(_sanitize_exception(exc))
        return {
            "ok": not errors,
            "stdout": stdout,
            "stdout_truncated": stdout_cut,
            "stderr": stderr,
            "stderr_truncated": stderr_cut,
            "errors": errors,
        }

    def namespace(self) -> Mapping[str, Any]:
        user_ns = self._kernel.shell.user_ns  # type: ignore[union-attr]
        return {
            name: value
            for name, value in user_ns.items()
            if not name.startswith("_") and name not in _NAMESPACE_IGNORABLE
        }

    def shutdown(self) -> None:
        # In-process kernels have no separate process to terminate.
        self._kernel.shell.atexit_operations = lambda: None  # type: ignore[union-attr, method-assign]


def _module_bound_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    bound: set[str] = set()
    imported: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                bound.add(name)
                imported.add(name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                bound.add(name)
                imported.add(name)
        else:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    bound.add(sub.id)
    return bound, imported


def export_candidate(source: str, selection: str | None = None) -> dict[str, Any]:
    """Re-derive a capability-package/v1 candidate from cell source (§41.54).

    The candidate must be a top-level ``def``/``class`` that closes over
    nothing except module imports and builtins; any other free variable
    fails closed with ``OPAQUE_DEPENDENCY``.
    """

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="cell source does not parse",
            details={"reason_code": "SYNTAX_ERROR", "line": exc.lineno},
        ) from exc

    candidates = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if selection is not None:
        chosen = [n for n in candidates if n.name == selection]
    elif len(candidates) == 1:
        chosen = candidates
    else:
        chosen = []
    if not chosen:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="export requires exactly one top-level def/class selection",
            details={
                "reason_code": "SELECTION_AMBIGUOUS",
                "candidates": sorted(n.name for n in candidates),
            },
        )
    node = chosen[0]

    module_bound, imported = _module_bound_names(tree)
    inner_bound = {
        sub.id
        for sub in ast.walk(node)
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store)
    }
    inner_bound.update(
        sub.arg for sub in ast.walk(node) if isinstance(sub, ast.arg)
    )
    free = sorted(
        {
            sub.id
            for sub in ast.walk(node)
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)
        }
        - inner_bound
        - module_bound
        - set(dir(builtins))
    )
    if free:
        raise StableError(
            code=ErrorCode.INVALID_ARGUMENT,
            message="selection depends on values that cannot be exported",
            details={"reason_code": "OPAQUE_DEPENDENCY", "free_variables": free},
        )

    return {
        "payload_type": "capability-package/v1",
        "trust_class": "trusted_candidate",
        "name": node.name,
        "kind": "class" if isinstance(node, ast.ClassDef) else "function",
        "source": ast.get_source_segment(source, node) or "",
        "imports": sorted(imported),
    }


class ScratchSessionController:
    """Realm-scoped owner of the single scratch session (§41.54).

    Persistence goes straight to the already-migrated scratch tables; the
    kernel itself is never reconstructed — a restart yields an unattached
    controller and a LOST session.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        realm_id: str,
        owner_principal_id: str,
        workspace_id: str = "workspace://scratch",
        clock_us: Callable[[], int] | None = None,
        kernel_factory: Callable[[], KernelWorker] | None = None,
    ) -> None:
        self._conn = conn
        self._realm_id = realm_id
        self._owner = owner_principal_id
        self._workspace_id = workspace_id
        self._clock_us = clock_us or (lambda: int(time.time() * 1_000_000))
        self._kernel_factory = kernel_factory
        self._kernel: KernelWorker | None = None
        self._cell_counter = 0
        self._reflector = SafeReflector()

    # ------------------------------------------------------------ create --
    def create_session(self) -> dict[str, Any]:
        now_us = self._clock_us()
        existing = self._conn.execute(
            "SELECT session_id FROM scratch_sessions"
            " WHERE realm_id = ? AND status IN ('STARTING','ACTIVE')",
            (self._realm_id,),
        ).fetchone()
        if existing is not None:
            raise StableError(
                code=ErrorCode.ALREADY_RUNNING,
                message="realm already owns a scratch session",
                details={"session_id": existing[0]},
            )
        session_id = "scratch://" + new_uuid7()
        self._conn.execute(
            "INSERT INTO scratch_sessions(session_id, realm_id, owner_principal_id,"
            " status, workspace_id, backend_request_id, idle_expires_at_us,"
            " wall_expires_at_us, last_activity_at_us, created_at_us, updated_at_us)"
            " VALUES (?, ?, ?, 'STARTING', ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                self._realm_id,
                self._owner,
                self._workspace_id,
                "scratch:" + new_uuid7(),
                now_us + IDLE_TTL_US,
                now_us + WALL_TTL_US,
                now_us,
                now_us,
                now_us,
            ),
        )
        if self._kernel_factory is not None:
            self._kernel = self._kernel_factory()
        self._conn.execute(
            "UPDATE scratch_sessions SET status = 'ACTIVE', updated_at_us = ?"
            " WHERE session_id = ?",
            (self._clock_us(), session_id),
        )
        self._conn.commit()
        return self.get_session(session_id)

    # ------------------------------------------------------------ execute --
    def execute(self, source: str) -> dict[str, Any]:
        session = self._require_active()
        issues = check_cell_source(source)
        if issues:
            raise StableError(
                code=ErrorCode.INVALID_ARGUMENT,
                message="cell source denied by scratch policy",
                details={"issues": list(issues)},
            )
        if self._kernel is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="no kernel attached to the session (restart is not recoverable)",
            )
        now_us = self._clock_us()
        self._cell_counter += 1
        cell_action_id = f"action://scratch/{session['session_id'].split('//', 1)[1]}/{self._cell_counter}"
        outcome = self._kernel.run_cell(source)
        before = self._load_bindings(session["session_id"])
        for name, value in self._kernel.namespace().items():
            generation = 1
            for record in before:
                if record.binding_name == name:
                    generation = record.generation + 1
            self._record_binding(session["session_id"], name, generation, value, cell_action_id)
        self._touch(session["session_id"], now_us)
        return {"cell_action_id": cell_action_id, **outcome}

    # ------------------------------------------------------------ inspect --
    def safe_inspect(self, name: str, budget: InspectBudget | None = None) -> Any:
        session = self._require_active()
        if self._kernel is None:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="no kernel attached to the session",
            )
        if name not in self._kernel.namespace():
            raise StableError(
                code=ErrorCode.NOT_FOUND,
                message="binding not present in the scratch namespace",
                details={"binding": name},
            )
        self._touch(session["session_id"], self._clock_us())
        return self._reflector.reflect(self._kernel.namespace()[name], budget)

    def bindings(self) -> tuple[BindingRecord, ...]:
        # history stays readable for terminal sessions (LOST/RELEASED)
        row = self._conn.execute(
            "SELECT session_id FROM scratch_sessions WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="no scratch session for realm"
            )
        return tuple(self._load_bindings(row[0]))

    # ---------------------------------------------------------- lifecycle --
    def cancel(self) -> dict[str, Any]:
        session = self._require_terminalable()
        self._set_status(session, "LOST")
        self._expire_bindings(session, "EXPIRED")
        self._drop_kernel()
        return self.get_session(session)

    def release(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT status FROM scratch_sessions WHERE realm_id = ?", (self._realm_id,)
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="no scratch session for realm"
            )
        if row[0] == "RELEASED":  # idempotent
            return self.get_session(self._session_id_for(self._realm_id))
        session = self._session_id_for(self._realm_id)
        self._set_status(session, "RELEASED")
        self._expire_bindings(session, "RELEASED")
        self._drop_kernel()
        return self.get_session(session)

    def expire_sessions(self, now_us: int | None = None) -> tuple[str, ...]:
        now = now_us if now_us is not None else self._clock_us()
        rows = self._conn.execute(
            "SELECT session_id FROM scratch_sessions"
            " WHERE realm_id = ? AND status IN ('STARTING','ACTIVE')"
            " AND (idle_expires_at_us <= ? OR wall_expires_at_us <= ?)",
            (self._realm_id, now, now),
        ).fetchall()
        expired = []
        for (session_id,) in rows:
            self._set_status(session_id, "LOST")
            self._expire_bindings(session_id, "EXPIRED")
            expired.append(session_id)
        if expired:
            self._drop_kernel()
        return tuple(expired)

    # ------------------------------------------------------------ queries --
    def get_session(self, session_id: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT session_id, realm_id, owner_principal_id, status, workspace_id,"
            " idle_expires_at_us, wall_expires_at_us, last_activity_at_us"
            " FROM scratch_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="unknown scratch session"
            )
        return {
            "session_id": row[0],
            "realm_id": row[1],
            "owner_principal_id": row[2],
            "status": row[3],
            "workspace_id": row[4],
            "idle_expires_at_us": row[5],
            "wall_expires_at_us": row[6],
            "last_activity_at_us": row[7],
        }

    # ------------------------------------------------------------ helpers --
    def _require_active(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT session_id, status FROM scratch_sessions WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="no scratch session for realm"
            )
        if row[1] not in _STATUS_ACTIVE:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message=f"scratch session is {row[1]}",
            )
        return self.get_session(row[0])

    def _require_terminalable(self) -> str:
        row = self._conn.execute(
            "SELECT session_id, status FROM scratch_sessions WHERE realm_id = ?",
            (self._realm_id,),
        ).fetchone()
        if row is None:
            raise StableError(
                code=ErrorCode.NOT_FOUND, message="no scratch session for realm"
            )
        if row[1] in ("RELEASED", "LOST"):
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message=f"scratch session already {row[1]}",
            )
        return row[0]

    def _session_id_for(self, realm_id: str) -> str:
        row = self._conn.execute(
            "SELECT session_id FROM scratch_sessions WHERE realm_id = ?", (realm_id,)
        ).fetchone()
        assert row is not None
        return row[0]

    def _load_bindings(self, session_id: str) -> list[BindingRecord]:
        rows = self._conn.execute(
            "SELECT session_id, binding_name, generation, type_module, type_name,"
            " source_artifact_id, last_cell_action_id, observed_handle_hash, status,"
            " metadata_json FROM scratch_bindings WHERE session_id = ?"
            " ORDER BY binding_name, generation",
            (session_id,),
        ).fetchall()
        return [BindingRecord(*row) for row in rows]

    def _record_binding(
        self,
        session_id: str,
        name: str,
        generation: int,
        value: Any,
        cell_action_id: str,
    ) -> None:
        value_type = type(value)
        handle = self._reflector.id_token(value)
        metadata = {"value_kind": getattr(value_type, "__name__", "unknown")}
        self._conn.execute(
            "INSERT INTO scratch_bindings(session_id, binding_name, generation,"
            " type_module, type_name, source_artifact_id, last_cell_action_id,"
            " observed_handle_hash, status, metadata_json)"
            " VALUES (?, ?, ?, ?, ?, '', ?, ?, 'LIVE', ?)",
            (
                session_id,
                name,
                generation,
                value_type.__module__,
                value_type.__qualname__,
                cell_action_id,
                handle,
                repr(metadata).encode("utf-8"),
            ),
        )

    def _expire_bindings(self, session_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE scratch_bindings SET status = ?"
            " WHERE session_id = ? AND status = 'LIVE'",
            (status, session_id),
        )

    def _touch(self, session_id: str, now_us: int) -> None:
        self._conn.execute(
            "UPDATE scratch_sessions SET last_activity_at_us = ?,"
            " idle_expires_at_us = ?, updated_at_us = ? WHERE session_id = ?",
            (now_us, now_us + IDLE_TTL_US, now_us, session_id),
        )
        self._conn.commit()

    def _set_status(self, session_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE scratch_sessions SET status = ?, updated_at_us = ?"
            " WHERE session_id = ?",
            (status, self._clock_us(), session_id),
        )
        self._conn.commit()

    def _drop_kernel(self) -> None:
        if self._kernel is not None:
            with contextlib.suppress(Exception):
                self._kernel.shutdown()
            self._kernel = None
