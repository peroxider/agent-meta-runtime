"""Step 07 gate: IPython Scratch adapter contract (§41.54)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.scratch_ipython import (
    ALLOWED_MAGICS,
    IDLE_TTL_US,
    OUTPUT_LIMIT_BYTES,
    WALL_TTL_US,
    InProcessIpykernel,
    ScratchSessionController,
    check_cell_source,
    execute_config,
    export_candidate,
    truncate_stream,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.reflection import InspectBudget

ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"


class FakeKernel:
    """Deterministic worker: exec the source in a plain namespace."""

    def __init__(self) -> None:
        self._ns: dict[str, object] = {}
        self.runs = 0

    def run_cell(self, source: str) -> dict[str, object]:
        self.runs += 1
        exec(compile(source, "<scratch>", "exec"), self._ns)  # noqa: S102
        return {"ok": True, "stdout": "", "stdout_truncated": False,
                "stderr": "", "stderr_truncated": False, "errors": []}

    def namespace(self) -> dict[str, object]:
        # worker contract: private/kernel-injected names are not bindings
        return {k: v for k, v in self._ns.items() if not k.startswith("_")}

    def shutdown(self) -> None:
        self._ns.clear()


# ------------------------------------------------------------ static gates --

def test_allowed_magics_are_exactly_the_spec_three():
    assert ALLOWED_MAGICS == frozenset({"%time", "%timeit", "%whos"})


def test_check_cell_source_allows_spec_magics_and_plain_code():
    assert check_cell_source("x = 1\n%time f()\n%whos\n") == ()
    assert check_cell_source("%timeit sum(range(10))") == ()


def test_check_cell_source_denies_other_magics_and_escapes():
    assert check_cell_source("%matplotlib inline") == ("scratch.magic:%matplotlib",)
    assert check_cell_source("%%bash\necho hi") == (
        "scratch.cell_magic:%%bash",
        "scratch.magic:%%bash",
    )
    assert check_cell_source("!ls -la") == ("scratch.escape:!",)
    assert check_cell_source("??sorted") == ("scratch.escape:?",)
    assert check_cell_source("/etc/passwd") == ("scratch.escape:/",)


def test_execute_config_never_stores_history():
    config = execute_config()
    assert config["store_history"] is False
    assert config["timeout_s"] > 0


def test_truncate_stream_caps_at_limit_and_is_utf8_safe():
    text, cut = truncate_stream("a" * 100)
    assert (text, cut) == ("a" * 100, False)
    payload = ("x" * (OUTPUT_LIMIT_BYTES + 10)).encode().decode()
    out, cut = truncate_stream(payload)
    assert cut is True
    assert len(out.encode()) <= OUTPUT_LIMIT_BYTES + len(b"\n...[truncated]")
    boundary = "é" * (OUTPUT_LIMIT_BYTES // 2 + 4)  # 2-byte codepoints straddle
    out, cut = truncate_stream(boundary)
    assert out.encode("utf-8")  # decodable round trip
    assert cut is True


# --------------------------------------------------------- export candidate --

SOURCE_CANDIDATE = """
import json

def helper(value):
    return json.dumps({"v": value})

def picker(value):
    return helper(value)
"""


def test_export_candidate_single_top_level_function():
    package = export_candidate("import json\n\ndef echo(v):\n    return json.dumps(v)\n")
    assert package["payload_type"] == "capability-package/v1"
    assert package["trust_class"] == "trusted_candidate"
    assert package["name"] == "echo"
    assert package["kind"] == "function"
    assert package["imports"] == ["json"]


def test_export_candidate_selection_by_name():
    package = export_candidate(SOURCE_CANDIDATE, selection="picker")
    assert package["name"] == "picker"
    assert package["source"].startswith("def picker")


def test_export_candidate_fails_closed_on_free_variable():
    with pytest.raises(StableError) as excinfo:
        export_candidate(
            "import json\n\ndef echo(v):\n    return json.dumps(v)\n\n"
            "def broken(v):\n    return helper(v)\n",
            selection="broken",
        )
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT
    assert excinfo.value.details["reason_code"] == "OPAQUE_DEPENDENCY"
    assert excinfo.value.details["free_variables"] == ["helper"]


def test_export_candidate_ambiguous_and_syntax_errors():
    with pytest.raises(StableError) as excinfo:
        export_candidate(SOURCE_CANDIDATE)
    assert excinfo.value.details["reason_code"] == "SELECTION_AMBIGUOUS"
    with pytest.raises(StableError) as excinfo:
        export_candidate("def broken(:\n    pass")
    assert excinfo.value.details["reason_code"] == "SYNTAX_ERROR"


# ------------------------------------------------------------- controller --

def _controller(store, kernel=None, clock=None):
    conn, realm, _tmp = store
    controller = ScratchSessionController(
        conn,
        realm_id=realm,
        owner_principal_id=ACTOR,
        kernel_factory=(lambda: kernel) if kernel is not None else None,
    )
    if clock is not None:
        controller._clock_us = clock
    return controller


def test_create_session_is_one_per_realm(store):
    controller = _controller(store)
    session = controller.create_session()
    assert session["status"] == "ACTIVE"
    assert session["realm_id"].startswith("realm://")
    with pytest.raises(StableError) as excinfo:
        _controller(store).create_session()
    assert excinfo.value.code == ErrorCode.ALREADY_RUNNING


def test_execute_records_binding_generations(store):
    kernel = FakeKernel()
    controller = _controller(store, kernel=kernel)
    controller.create_session()
    first = controller.execute("value = [1, 2, 3]\n")
    assert first["ok"] is True
    bindings = controller.bindings()
    assert [b.binding_name for b in bindings] == ["value"]
    assert bindings[0].generation == 1
    assert bindings[0].type_name == "list"
    assert bindings[0].status == "LIVE"
    controller.execute("value = [4]\n")
    bindings = controller.bindings()
    # PK(session, binding, generation): history accumulates, latest wins
    assert [b.generation for b in bindings] == [1, 2]


def test_execute_denies_policy_violating_cells(store):
    controller = _controller(store, kernel=FakeKernel())
    controller.create_session()
    with pytest.raises(StableError) as excinfo:
        controller.execute("!ls\n")
    assert excinfo.value.code == ErrorCode.INVALID_ARGUMENT
    assert controller._kernel.runs == 0


def test_safe_inspect_reflects_and_fails_closed_on_unknown(store):
    controller = _controller(store, kernel=FakeKernel())
    controller.create_session()
    controller.execute("numbers = [1, 2]\n")
    node = controller.safe_inspect("numbers", InspectBudget(max_depth=2))
    assert node.kind == "container"
    with pytest.raises(StableError) as excinfo:
        controller.safe_inspect("missing")
    assert excinfo.value.code == ErrorCode.NOT_FOUND


def test_cancel_expires_session_and_bindings(store):
    controller = _controller(store, kernel=FakeKernel())
    controller.create_session()
    controller.execute("a = 1\n")
    session = controller.cancel()
    assert session["status"] == "LOST"
    assert all(b.status == "EXPIRED" for b in controller.bindings())
    with pytest.raises(StableError) as excinfo:
        controller.execute("b = 2\n")
    assert excinfo.value.code == ErrorCode.FAILED_PRECONDITION


def test_release_is_idempotent_and_terminal(store):
    controller = _controller(store, kernel=FakeKernel())
    controller.create_session()
    assert controller.release()["status"] == "RELEASED"
    assert controller.release()["status"] == "RELEASED"
    with pytest.raises(StableError):
        controller.cancel()


def test_idle_ttl_expiry_marks_session_lost(store):
    controller = _controller(store, kernel=FakeKernel())
    controller.create_session()
    assert controller.expire_sessions() == ()  # fresh session, no expiry
    session_id = controller._session_id_for("realm://main")
    session = controller.get_session(session_id)
    future = session["idle_expires_at_us"] + 1
    assert controller.expire_sessions(now_us=future) != ()
    assert controller.get_session(session["session_id"])["status"] == "LOST"
    with pytest.raises(StableError):
        controller.execute("x = 1\n")


def test_ttl_constants_match_spec():
    assert IDLE_TTL_US == 30 * 60 * 1_000_000
    assert WALL_TTL_US == 4 * 3600 * 1_000_000
    assert OUTPUT_LIMIT_BYTES == 1024 * 1024


def test_in_process_kernel_requires_ipykernel():
    try:
        import ipykernel  # noqa: F401
    except ImportError:
        with pytest.raises(StableError) as excinfo:
            InProcessIpykernel()
        assert excinfo.value.code == ErrorCode.FEATURE_UNAVAILABLE
        return
    worker = InProcessIpykernel()
    outcome = worker.run_cell("value = 40 + 2\n")
    assert outcome["ok"] is True
    assert worker.namespace()["value"] == 42
    worker.shutdown()
