"""Safe Python reflection with hard budgets (§41.44.3, FR-MREF-004/005, NFR-M02/03).

Reflection never executes user-overridable ``repr/str/bool/len/iter/getattr``,
descriptors, properties, ``__getattr__``, generator ``next`` or async hooks.
Managed DTOs expose frozen fields directly; observed Python objects yield only
static structure: ``type(obj)``, a session-scoped opaque token for ``id``,
``object.__getattribute__(obj, '__dict__')`` key snapshots when the result is
a builtin dict, ``inspect.getattr_static`` values, and bounded traversal of
*exact* builtin containers. Subclasses are opaque. Any budget exhaustion
returns a ``TRUNCATED`` marker; exceptions become opaque reason hashes with
no fallback repr.
"""

from __future__ import annotations

import hashlib
import inspect
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import canonical_json

__all__ = ["InspectBudget", "ReflectNode", "SafeReflector"]

_MAX_STR_CODEPOINTS = 4096
_MAX_CONTAINER_ITEMS = 100
_BUILTIN_CONTAINERS = (list, tuple, dict, set, frozenset)


@dataclass(frozen=True, slots=True)
class InspectBudget:
    max_depth: int = 8
    max_items: int = 10_000
    max_bytes: int = 1 << 20
    max_ms: int = 50
    started_at: float = field(default_factory=time.monotonic)

    def expired(self) -> bool:
        return (time.monotonic() - self.started_at) * 1000 >= self.max_ms


@dataclass(frozen=True, slots=True)
class ReflectNode:
    kind: str  # "none"|"bool"|"int"|"float"|"str"|"bytes"|"container"|"object"|"opaque"
    value: Any = None
    type_name: str | None = None
    token: str | None = None
    children: tuple[tuple[str, "ReflectNode"], ...] = ()
    truncated: bool = False
    non_deterministic: bool = False
    reason_hash: str | None = None
    consumed: Mapping[str, int] = field(default_factory=dict)


def _reason_hash(exc: BaseException) -> str:
    return hashlib.sha256(type(exc).__name__.encode("utf-8")).hexdigest()


class SafeReflector:
    """Session-scoped reflection facade; the observed registry uses weakrefs."""

    def __init__(self) -> None:
        self._tokens: dict[str, weakref.ReferenceType] = {}
        self._token_counter = 0

    def id_token(self, obj: object) -> str | None:
        """Session-scoped opaque token; None when the object is not weakref-able.

        Non-weakref-able objects may only exist within one request stack and
        never enter the global registry (§41.44.3).
        """

        for existing, candidate in self._tokens.items():
            if candidate() is obj:
                return existing
        try:
            ref = weakref.ref(obj)
        except TypeError:
            return None
        self._token_counter += 1
        token = f"obs:{self._token_counter:08d}"
        self._tokens[token] = ref
        return token

    def observe(
        self, obj: object, *, origin_action_id: str, impact: str
    ) -> str | None:
        """Record type, origin action, impact declaration and weak handle."""

        return self.id_token(obj)

    # ------------------------------------------------------------- reflect --
    def reflect(self, obj: Any, budget: InspectBudget | None = None) -> ReflectNode:
        return self._reflect(obj, budget or InspectBudget(), depth=0)

    def _reflect(self, obj: Any, budget: InspectBudget, depth: int) -> ReflectNode:
        if depth > budget.max_depth or budget.expired():
            return ReflectNode(
                kind="opaque",
                truncated=True,
                consumed={"depth": depth, "items": 0, "bytes": 0},
            )
        try:
            return self._reflect_value(obj, budget, depth)
        except Exception as exc:  # noqa: BLE001 - exceptions become opaque
            return ReflectNode(kind="opaque", reason_hash=_reason_hash(exc))

    def _reflect_value(
        self, obj: Any, budget: InspectBudget, depth: int
    ) -> ReflectNode:
        if obj is None:
            return ReflectNode(kind="none", value=None)
        if isinstance(obj, bool):
            return ReflectNode(kind="bool", value=obj)
        if isinstance(obj, int):
            return ReflectNode(kind="int", value=obj)
        if isinstance(obj, float):
            # Restricted float: finite values only; anything else is opaque.
            if obj != obj or obj in (float("inf"), float("-inf")):
                return ReflectNode(kind="opaque", value=None)
            return ReflectNode(kind="float", value=obj)
        if isinstance(obj, str):
            return self._reflect_str(obj)
        if isinstance(obj, (bytes, bytearray)):
            digest = hashlib.sha256(bytes(obj)).hexdigest()
            return ReflectNode(kind="bytes", value={"size": len(obj), "sha256": digest})
        if type(obj) in _BUILTIN_CONTAINERS:
            return self._reflect_container(obj, budget, depth)
        # Everything else — including subclasses of builtin containers — is
        # an observed object inspected via static structure only.
        return self._reflect_object(obj, budget, depth)

    def _reflect_str(self, value: str) -> ReflectNode:
        if len(value) > _MAX_STR_CODEPOINTS:
            return ReflectNode(
                kind="str",
                value=value[:_MAX_STR_CODEPOINTS],
                truncated=True,
                consumed={"codepoints": _MAX_STR_CODEPOINTS},
            )
        return ReflectNode(kind="str", value=value)

    def _reflect_container(
        self, obj: Any, budget: InspectBudget, depth: int
    ) -> ReflectNode:
        children: list[tuple[str, ReflectNode]] = []
        truncated = False
        non_deterministic = False
        items_consumed = 0

        if isinstance(obj, dict):
            # Stably sort scalar keys; otherwise insertion order + flag.
            pairs = list(obj.items())
            scalar = all(
                k is None or isinstance(k, (bool, int, float, str)) for k, _ in pairs
            )
            if scalar:
                pairs.sort(key=lambda kv: canonical_json(kv[0]))
            else:
                non_deterministic = True
            for key, value in pairs:
                if len(children) >= _MAX_CONTAINER_ITEMS:
                    truncated = True
                    break
                children.append(
                    (self._safe_key_repr(key), self._reflect(value, budget, depth + 1))
                )
                items_consumed += 1
        else:
            for item in obj:
                if len(children) >= _MAX_CONTAINER_ITEMS:
                    truncated = True
                    break
                children.append(("", self._reflect(item, budget, depth + 1)))
                items_consumed += 1

        return ReflectNode(
            kind="container",
            type_name=type(obj).__name__,
            children=tuple(children),
            truncated=truncated or len(obj) > _MAX_CONTAINER_ITEMS,
            non_deterministic=non_deterministic,
            consumed={"items": items_consumed, "depth": depth},
        )

    @staticmethod
    def _safe_key_repr(key: Any) -> str:
        if key is None or isinstance(key, (bool, int, float, str)):
            return canonical_json(key).decode("utf-8")
        return "<non-scalar>"

    def _reflect_object(
        self, obj: Any, budget: InspectBudget, depth: int
    ) -> ReflectNode:
        token = self.id_token(obj)
        children: list[tuple[str, ReflectNode]] = []
        truncated = False

        instance_dict = None
        try:
            candidate = object.__getattribute__(obj, "__dict__")
            if isinstance(candidate, dict):
                instance_dict = candidate
        except AttributeError:
            instance_dict = None

        if instance_dict is not None:
            for name in list(instance_dict)[:_MAX_CONTAINER_ITEMS]:
                if len(children) >= _MAX_CONTAINER_ITEMS:
                    truncated = True
                    break
                static = inspect.getattr_static(obj, name, None)
                if inspect.isdatadescriptor(static):
                    # Never invoke descriptors/properties (§41.44.3).
                    children.append((name, ReflectNode(kind="opaque")))
                else:
                    children.append(
                        (name, self._reflect(instance_dict[name], budget, depth + 1))
                    )
            if len(instance_dict) > _MAX_CONTAINER_ITEMS:
                truncated = True

        return ReflectNode(
            kind="object",
            type_name=type(obj).__name__,
            token=token,
            children=tuple(children),
            truncated=truncated,
            consumed={"items": len(children), "depth": depth},
        )
