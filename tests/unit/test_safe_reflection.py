"""Step 02 gate: safe Python reflection budgets (§41.44.3, FR-MREF-004/005)."""

from __future__ import annotations

from agent_meta_runtime.domain.reflection import InspectBudget, SafeReflector


class Evil:
    """Every user override raises; reflection must never invoke them."""

    def __repr__(self) -> str:  # pragma: no cover - must never run
        raise AssertionError("__repr__ invoked")

    def __str__(self) -> str:  # pragma: no cover - must never run
        raise AssertionError("__str__ invoked")

    def __len__(self) -> int:  # pragma: no cover - must never run
        raise AssertionError("__len__ invoked")

    def __getattr__(self, name):  # pragma: no cover - must never run
        raise AssertionError(f"__getattr__ invoked for {name}")

    @property
    def prop(self):  # pragma: no cover - must never run
        raise AssertionError("property invoked")

    def __iter__(self):  # pragma: no cover - must never run
        raise AssertionError("__iter__ invoked")


def _evil_instance() -> Evil:
    evil = Evil.__new__(Evil)
    object.__setattr__(evil, "value", 42)
    return evil


def test_object_reflection_never_invokes_user_code():
    reflector = SafeReflector()
    node = reflector.reflect(_evil_instance())
    assert node.kind == "object"
    assert node.token is not None
    children = dict(node.children)
    assert "value" in children
    assert children["value"].kind == "int"
    # Only instance __dict__ keys are surfaced; class descriptors (properties)
    # never appear and are never invoked.
    assert "prop" not in children


def test_id_token_is_session_scoped_and_stable():
    reflector = SafeReflector()
    obj = _evil_instance()
    token1 = reflector.id_token(obj)
    token2 = reflector.id_token(obj)
    assert token1 == token2
    assert token1.startswith("obs:")
    # Non-weakref-able objects stay request-local: no token.
    assert reflector.id_token(42) is None
    # Tokens are opaque handles, not object identity across sessions.
    other = SafeReflector().id_token(obj)
    assert other is not None and other.startswith("obs:")


def test_builtin_containers_bounded_and_sorted():
    reflector = SafeReflector()
    node = reflector.reflect(list(range(500)))
    assert node.kind == "container"
    assert node.truncated is True
    assert len(node.children) == 100
    dict_node = reflector.reflect({"b": 1, "a": 2, 10: 3})
    keys = [k for k, _ in dict_node.children]
    # Scalar keys sort stably by canonical JSON bytes: quoted strings first.
    assert keys == ['"a"', '"b"', "10"]


def test_non_scalar_dict_keys_flag_non_determinism():
    reflector = SafeReflector()
    node = reflector.reflect({(1, 2): "tuple-key", "s": 1})
    assert node.non_deterministic is True
    assert dict(node.children)["<non-scalar>"].kind == "str"


def test_scalar_payloads():
    reflector = SafeReflector()
    assert reflector.reflect(None).kind == "none"
    assert reflector.reflect(True).kind == "bool"
    assert reflector.reflect(7).kind == "int"
    assert reflector.reflect(float("inf")).kind == "opaque"
    assert reflector.reflect(1.5).kind == "float"
    long_str = "x" * 5000
    node = reflector.reflect(long_str)
    assert node.truncated and len(node.value) == 4096
    blob = reflector.reflect(b"secret-bytes")
    assert blob.kind == "bytes"
    assert blob.value["size"] == len(b"secret-bytes")
    assert "sha256" in blob.value


def test_subclass_of_builtin_container_is_opaque_object():
    class MyList(list):
        pass

    reflector = SafeReflector()
    node = reflector.reflect(MyList([1, 2, 3]))
    # Subclasses are observed objects: static structure only, no traversal
    # of the container's items through the builtin iterator.
    assert node.kind == "object"
    assert node.type_name == "MyList"


def test_depth_budget_truncates():
    reflector = SafeReflector()
    deep = {"a": {"b": {"c": {"d": "leaf"}}}}

    def has_deep_truncation(node) -> bool:
        if node.truncated:
            return True
        return any(has_deep_truncation(child) for _, child in node.children)

    assert has_deep_truncation(reflector.reflect(deep, InspectBudget(max_depth=2)))
    assert not has_deep_truncation(reflector.reflect(deep))


def test_time_budget_expires():
    reflector = SafeReflector()
    # A zero-millisecond budget expires immediately.
    node = reflector.reflect({"a": 1}, InspectBudget(max_ms=0))
    assert node.kind == "opaque"
    assert node.truncated is True


def test_observe_records_session_handle():
    reflector = SafeReflector()
    obj = _evil_instance()
    token = reflector.observe(obj, origin_action_id="action://x", impact="read")
    assert token == reflector.id_token(obj)
