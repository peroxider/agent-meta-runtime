"""Actual CPython stores, including extended args and hostile code constants."""

import sys

from agent_meta_runtime.adapters.scratch_binding_trace import BindingWriteTrace
from agent_meta_runtime.domain.scratch_observation import ScratchObserver


def cell(observer, namespace, code):
    observer.begin_cell(namespace)
    with BindingWriteTrace(namespace) as trace:
        exec(code, namespace)
    observer.end_cell(namespace, trace.writes, trace.complete)
    return trace


def test_binding_store_generations_creation_deletion_and_global_function_writes():
    observer, namespace = ScratchObserver(), {}
    cell(observer, namespace, "pass")  # fixed bootstrap ordinal
    cell(
        observer,
        namespace,
        "value=[]\nunchanged=7\ndef update():\n global value\n value=42",
    )
    one = {
        row["name"]: row
        for row in observer.request(namespace, {"operation": "bindings"})["result"][
            "bindings"
        ]
    }
    cell(observer, namespace, "update()")
    two = {
        row["name"]: row
        for row in observer.request(namespace, {"operation": "bindings"})["result"][
            "bindings"
        ]
    }
    assert one["value"]["created_cell"] == two["value"]["created_cell"] == 2
    assert (
        two["value"]["last_changed_cell"] == 3
        and two["value"]["binding_generation"] == 2
    )
    assert (
        two["unchanged"]["last_changed_cell"] == 2
        and two["unchanged"]["binding_generation"] == 1
    )
    cell(observer, namespace, "del value")
    assert "value" not in observer._metadata
    cell(observer, namespace, "value=9")
    assert observer._metadata["value"] == {
        "created_cell": 5,
        "last_changed_cell": 5,
        "binding_generation": 3,
    }


def test_trace_decodes_extended_name_arguments_without_repr_or_hashing_constants():
    calls = []

    class Hostile:
        def __repr__(self):
            calls.append("repr")
            raise RuntimeError("repr")

        def __hash__(self):
            calls.append("hash")
            raise RuntimeError("hash")

    namespace = {}
    code = compile("value=1", "<fixture>", "exec").replace(co_consts=(Hostile(), None))
    previous = sys.gettrace()
    with BindingWriteTrace(namespace) as trace:
        exec(code, namespace)
    assert trace.writes == {"value"} and calls == [] and sys.gettrace() is previous
    namespace = {}
    with BindingWriteTrace(namespace) as trace:
        exec("\n".join(f"name_{index}=1" for index in range(300)), namespace)
    assert len(trace.writes) == 300 and "name_299" in trace.writes


def test_namespace_tracking_retains_only_identity_metadata_and_marks_disabled_trace():
    namespace = {}
    observer = ScratchObserver()
    cell(observer, namespace, "pass")
    observer.begin_cell(namespace)
    with BindingWriteTrace(namespace) as trace:
        exec("import sys\nvalue=1\nsys.settrace(None)\nvalue=2", namespace)
    observer.end_cell(namespace, trace.writes, trace.complete)
    assert not trace.complete and not observer.tracking_complete
    assert observer._before == {}
