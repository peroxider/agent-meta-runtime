"""Bounded static Python reflection (§41.44.3).

Only exact builtin values are traversed. User descriptors, scalar subclasses,
metaclass attribute hooks and container overrides never participate. A single
request ledger bounds the whole traversal, including cycles and shared graphs.
Observed handles hold weak references and are unique to this reflector session.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import itertools
import math
import time
import types
import uuid
import weakref
from typing import Any, Mapping

from .canonical import canonical_json

__all__ = ["InspectBudget", "ReflectNode", "SafeReflector", "reflection_document", "exact_type_names"]

_TYPE_DICT = type.__dict__["__dict__"]
_TYPE_MRO = type.__dict__["__mro__"]
_TYPE_NAME = type.__dict__["__name__"]
_CONTAINERS = (list, tuple, dict, set, frozenset)
_MAX_HANDLES = 4096
_NODE_BYTES = 512
_MISSING = object()
_UNKNOWN = object()


@dataclass(frozen=True, slots=True)
class InspectBudget:
    max_depth: int = 8
    max_items: int = 10_000
    max_bytes: int = 1 << 20
    max_ms: int = 50
    started_at: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        for value, ceiling in ((self.max_depth,32),(self.max_items,10_000),
                (self.max_bytes,1 << 20),(self.max_ms,50)):
            if type(value) is not int or not 0<=value<=ceiling:
                raise ValueError("invalid inspection budget")
        if (type(self.started_at) is not int and type(self.started_at) is not float) or not math.isfinite(self.started_at):
            raise ValueError("invalid inspection clock")

    def expired(self) -> bool:
        return (time.monotonic()-self.started_at)*1000>=self.max_ms


@dataclass(frozen=True, slots=True)
class ReflectNode:
    kind: str
    value: Any = None
    type_name: str | None = None
    token: str | None = None
    children: tuple[tuple[str,"ReflectNode"], ...] = ()
    truncated: bool = False
    non_deterministic: bool = False
    reason_hash: str | None = None
    consumed: Mapping[str,int] = field(default_factory=dict)


def exact_type_names(obj):
    """Read builtin type storage, bypassing metaclass properties and overrides."""
    cls = type(obj)
    # CPython's type-name slot can retain a str subclass supplied through
    # type.__setattr__. Use the builtin string operation, never its overrides.
    name = str.__getitem__(_TYPE_NAME.__get__(cls),slice(0,128))
    module = _namespace_value(_TYPE_DICT.__get__(cls),"__module__")
    module = module[:128] if type(module) is str else "unknown"
    return module.encode('utf-8','replace').decode(),name.encode('utf-8','replace').decode()


def _namespace_value(namespace,name):
    # A class namespace may retain a str subclass key with hostile equality.
    # Bounded iteration avoids invoking it during a dictionary lookup.
    for key,value in itertools.islice(namespace.items(),256):
        if type(key) is str and key==name:
            return value
    return _MISSING


def _class_attribute(cls, name):
    for parent in itertools.islice(_TYPE_MRO.__get__(cls),32):
        namespace = _TYPE_DICT.__get__(parent)
        value = _namespace_value(namespace,name)
        if value is not _MISSING:
            return value
        if len(namespace)>256:
            return _UNKNOWN
    return _UNKNOWN if len(_TYPE_MRO.__get__(cls))>32 else None


def _instance_dictionary(obj):
    descriptor = _class_attribute(type(obj),"__dict__")
    # A user property or descriptor named __dict__ is never evaluated.
    if type(descriptor) is not types.GetSetDescriptorType or descriptor.__name__!="__dict__":
        return None
    candidate = object.__getattribute__(obj,"__dict__")
    return candidate if type(candidate) is dict else None


def _data_descriptor(value):
    if value is _UNKNOWN:
        return True
    cls = type(value)
    return _class_attribute(cls,"__get__") is not None and (
        _class_attribute(cls,"__set__") is not None or _class_attribute(cls,"__delete__") is not None)


def reflection_document(node: ReflectNode):
    """Convert Runtime-owned nodes, without dataclass deepcopy hooks."""
    return {"kind":node.kind,"value":node.value,"type_name":node.type_name,
        "token":node.token,"children":[[key,reflection_document(child)] for key,child in node.children],
        "truncated":node.truncated,"non_deterministic":node.non_deterministic,
        "reason_hash":node.reason_hash,"consumed":dict(node.consumed)}


class _Ledger:
    def __init__(self,budget):
        self.budget = budget
        self.items = self.bytes = self.depth = 0
        self.active = set()

    def consume(self, size=0, *, item=False, depth=0):
        if (self.budget.expired() or depth>self.budget.max_depth
                or self.items+int(item)>self.budget.max_items or self.bytes+size>self.budget.max_bytes):
            return False
        self.items += int(item)
        self.bytes += size
        self.depth = max(self.depth,depth)
        return True

    def snapshot(self):
        return {"items":self.items,"bytes":self.bytes,"depth":self.depth}


class SafeReflector:
    def __init__(self):
        self._tokens = {}
        self._identities = {}
        self._session = uuid.uuid4().hex
        self._token_counter = 0

    def id_token(self,obj):
        identity = id(obj)
        known = self._identities.get(identity)
        if known is not None and self._tokens[known]() is obj:
            return known
        if len(self._tokens)>=_MAX_HANDLES:
            return None
        self._token_counter += 1
        token = f"obs:{self._session}:{self._token_counter:08x}"
        def expired(reference):
            if self._tokens.get(token) is reference:
                self._tokens.pop(token,None)
                self._identities.pop(identity,None)
        try:
            reference = weakref.ref(obj,expired)
        except TypeError:
            return None
        self._tokens[token] = reference
        self._identities[identity] = token
        return token

    def resolve(self,token):
        if type(token) is not str:
            return None
        reference = self._tokens.get(token)
        return reference() if reference is not None else None

    def clear(self):
        self._tokens.clear()
        self._identities.clear()
        self._session = uuid.uuid4().hex

    def observe(self,obj,*,origin_action_id,impact):
        return self.id_token(obj)

    def reflect(self,obj,budget=None):
        if budget is not None and type(budget) is not InspectBudget:
            raise ValueError("inspection requires a fixed budget")
        ledger = _Ledger(budget if budget is not None else InspectBudget())
        node = self._reflect(obj,ledger,0)
        node = replace(node,consumed=ledger.snapshot())
        if len(canonical_json(reflection_document(node)))>ledger.budget.max_bytes:
            # The fixed truncation marker itself is outside a caller's zero or
            # tiny payload budget; no observed payload survives this fallback.
            return ReflectNode('opaque',truncated=True,consumed=ledger.snapshot())
        return node

    def _reflect(self,obj,ledger,depth):
        if not ledger.consume(_NODE_BYTES,item=True,depth=depth):
            return ReflectNode("opaque",truncated=True,consumed=ledger.snapshot())
        try:
            return self._value(obj,ledger,depth)
        except Exception as error:
            name = str.__getitem__(_TYPE_NAME.__get__(type(error)),slice(0,128))
            return ReflectNode("opaque",reason_hash=hashlib.sha256(name.encode()).hexdigest())

    def _value(self,obj,ledger,depth):
        kind = type(obj)
        if obj is None:
            return ReflectNode("none")
        if kind is bool:
            return ReflectNode("bool",value=obj)
        if kind is int:
            return ReflectNode("int",value=obj) if -(2**53-1)<=obj<=2**53-1 else ReflectNode("opaque")
        if kind is float:
            return ReflectNode("float",value=obj) if math.isfinite(obj) else ReflectNode("opaque")
        if kind is str:
            text = obj[:4096]
            remaining = ledger.budget.max_bytes-ledger.bytes
            lower,upper = 0,len(text)
            while lower<upper:
                middle = (lower+upper+1)//2
                if len(canonical_json(text[:middle]))<=remaining:
                    lower = middle
                else:
                    upper = middle-1
            text = text[:lower]
            if not ledger.consume(len(canonical_json(text))):
                return ReflectNode("opaque",truncated=True)
            return ReflectNode("str",value=text,truncated=len(text)<len(obj))
        if kind is bytes or kind is bytearray:
            if not ledger.consume(len(obj)):
                return ReflectNode("opaque",truncated=True)
            return ReflectNode("bytes",value={"size":len(obj),"sha256":hashlib.sha256(obj).hexdigest()})
        if any(kind is builtin for builtin in _CONTAINERS):
            return self._container(obj,ledger,depth)
        return self._object(obj,ledger,depth)

    def _key(self,key,remaining):
        if key is None or type(key) is bool or type(key) is int and -(2**53-1)<=key<=2**53-1:
            return canonical_json(key).decode()
        if type(key) is float and math.isfinite(key):
            return canonical_json(key).decode()
        if type(key) is str and len(key)<=min(4096,max(0,remaining)//6):
            return canonical_json(key).decode()
        return None

    def _container(self,obj,ledger,depth):
        if id(obj) in ledger.active:
            return ReflectNode("opaque",truncated=True)
        ledger.active.add(id(obj))
        try:
            if type(obj) is dict:
                snapshot,stable = [],True
                for key,value in itertools.islice(dict.items(obj),min(100,ledger.budget.max_items-ledger.items)):
                    label = self._key(key,ledger.budget.max_bytes-ledger.bytes)
                    stable = stable and label is not None
                    label = label if label is not None else "<non-scalar>"
                    if not ledger.consume(len(canonical_json(label))):
                        break
                    snapshot.append((label,value))
                stable = stable and len(obj)==len(snapshot)
                if stable:
                    snapshot.sort(key=lambda pair:pair[0].encode())
            else:
                snapshot = [("",value) for value in itertools.islice(obj,100)]
                stable = type(obj) is not set and type(obj) is not frozenset
            return self._children(snapshot,len(obj)>len(snapshot),not stable,ledger,depth,
                precharged=type(obj) is dict,
                kind="container",type_name=exact_type_names(obj)[1])
        finally:
            ledger.active.remove(id(obj))

    def _children(self,snapshot,truncated,non_deterministic,ledger,depth,precharged=False,**fields):
        children = []
        for label,value in snapshot:
            if (ledger.items>=ledger.budget.max_items or ledger.bytes+_NODE_BYTES>ledger.budget.max_bytes
                    or depth>=ledger.budget.max_depth
                    or not ledger.consume(0 if precharged else len(canonical_json(label)))):
                truncated = True
                break
            child = self._reflect(value,ledger,depth+1)
            children.append((label,child))
            truncated = truncated or child.truncated
            if ledger.budget.expired():
                truncated = True
                break
        return ReflectNode(children=tuple(children),truncated=truncated,
            non_deterministic=non_deterministic,consumed=ledger.snapshot(),**fields)

    def _object(self,obj,ledger,depth):
        if id(obj) in ledger.active:
            return ReflectNode("opaque",truncated=True)
        ledger.active.add(id(obj))
        try:
            dictionary = _instance_dictionary(obj)
            snapshot,placeholders = [],set()
            truncated = False
            if dictionary is not None:
                truncated = len(dictionary)>100
                for name,value in itertools.islice(dict.items(dictionary),100):
                    if ledger.budget.expired():
                        truncated = True
                        break
                    if type(name) is not str or len(name)>4096:
                        truncated = True
                        continue
                    if _data_descriptor(_class_attribute(type(obj),name)):
                        placeholders.add(name)
                        value = None
                    snapshot.append((name,value))
            node = self._children(snapshot,truncated,False,ledger,depth,
                kind="object",type_name=exact_type_names(obj)[1],token=self.id_token(obj))
            return replace(node,children=tuple((name,ReflectNode("opaque") if name in placeholders else child)
                for name,child in node.children))
        finally:
            ledger.active.remove(id(obj))
