"""Global reflection limits and hook canaries required by Scratch inspection."""
import gc
import weakref

import pytest

from agent_meta_runtime.domain.canonical import canonical_json
from agent_meta_runtime.domain.reflection import (
    InspectBudget,SafeReflector,exact_type_names,reflection_document,
)


@pytest.mark.parametrize('base', [str,int,float,bytes,bytearray,list,tuple,dict,set,frozenset])
def test_builtin_subclasses_never_execute_scalar_or_container_hooks(base):
    calls = []
    def hook(*args,**kwargs):
        calls.append('executed')
        raise AssertionError('user hook executed')
    cls = type('Hostile',(base,),{name:hook for name in (
        '__repr__','__str__','__len__','__iter__','__getitem__','__eq__','__le__','__ge__','__bytes__')})
    node = SafeReflector().reflect(cls())
    assert calls==[] and node.kind=='object' and node.type_name=='Hostile'
    canonical_json(reflection_document(node))


def test_instance_dictionary_property_and_metaclass_hooks_are_never_called():
    calls = []
    class Meta(type):
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError('metaclass lookup')
        def __eq__(self,other):
            calls.append('equality')
            raise AssertionError('metaclass equality')
    class Value(metaclass=Meta):
        @property
        def __dict__(self):
            calls.append('dictionary property')
            raise AssertionError('dictionary descriptor')
        @property
        def __class__(self):
            calls.append('class property')
            raise AssertionError('class descriptor')
    value = Value()
    node = SafeReflector().reflect(value)
    assert node.kind=='object' and node.type_name=='Value' and calls==[]
    assert exact_type_names(value)==(__name__,'Value')


def test_hidden_dictionary_descriptor_beyond_static_scan_limit_is_not_executed():
    calls = []
    class Parent:
        pass
    namespace = {f'field_{index}':index for index in range(300)}
    namespace['__dict__'] = property(lambda self:calls.append('descriptor'))
    value = type('Large',(Parent,),namespace)()
    assert SafeReflector().reflect(value).kind=='object' and calls==[]


def test_metaclass_properties_and_instance_attribute_override_are_not_executed():
    calls = []
    class Meta(type):
        @property
        def __name__(self):
            calls.append('type name')
            raise AssertionError('metaclass name property')
        @property
        def __dict__(self):
            calls.append('type dict')
            raise AssertionError('metaclass dictionary property')
    class Value(metaclass=Meta):
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError('instance attribute hook')
    value = Value()
    object.__setattr__(value,'field',42)
    node = SafeReflector().reflect(value)
    assert node.kind=='object' and node.type_name=='Value' and calls==[]
    assert dict(node.children)['field'].value==42


def test_type_name_storage_cannot_execute_a_retained_string_subclass():
    calls = []
    class Name(str):
        def __getitem__(self,key):
            calls.append('slice')
            raise AssertionError('type-name string slice')
        def encode(self,*args,**kwargs):
            calls.append('encode')
            raise AssertionError('type-name string encoding')
    class Value:
        pass
    type.__setattr__(Value,'__name__',Name('Renamed'))
    value = Value()
    assert exact_type_names(value)==(__name__,'Renamed')
    node = SafeReflector().reflect(value)
    assert node.type_name=='Renamed' and calls==[]


def test_hostile_class_namespace_keys_never_participate_in_lookup_equality():
    calls = []
    class Key(str):
        __hash__ = str.__hash__
        def __eq__(self,other):
            calls.append('equality')
            raise AssertionError('namespace key equality')
    cls = type('Value',(),{Key('target'):42})
    value = cls()
    value.target = 'own value'
    calls.clear()
    node = SafeReflector().reflect(value)
    assert node.kind=='object' and calls==[]


def test_item_and_byte_budgets_cover_the_complete_shared_graph():
    value = [['x'*1000 for _ in range(100)] for _ in range(100)]
    budget = InspectBudget(max_items=7,max_bytes=4096)
    node = SafeReflector().reflect(value,budget)
    assert node.truncated
    assert node.consumed['items']<=7 and node.consumed['bytes']<=4096
    def count(item):
        return 1+sum(count(child) for _,child in item.children)
    assert count(node)<=8  # At most one terminal truncation marker.
    assert len(canonical_json(reflection_document(node)))<4096


def test_cycles_end_without_visiting_the_same_heap_recursively():
    value = []
    value.append(value)
    node = SafeReflector().reflect(value)
    assert node.truncated and len(node.children)==1 and node.children[0][1].truncated
    assert node.consumed['items']==2


def test_time_budget_also_stops_static_attribute_metadata_scans(monkeypatch):
    import agent_meta_runtime.domain.reflection as module
    class Value:
        pass
    value = Value()
    for index in range(100):
        setattr(value,f'field_{index}',index)
    ticks,calls = [0.0],[]
    original = module._class_attribute
    def attribute(cls,name):
        calls.append(name)
        return original(cls,name)
    def monotonic():
        ticks[0] += .001
        return ticks[0]
    monkeypatch.setattr(module,'_class_attribute',attribute)
    monkeypatch.setattr(module.time,'monotonic',monotonic)
    node = SafeReflector().reflect(value,InspectBudget(max_ms=3,started_at=0))
    assert node.truncated and len(calls)<10


def test_oversized_bytes_are_not_hashed_outside_the_inspection_budget(monkeypatch):
    import agent_meta_runtime.domain.reflection as module
    calls = []
    monkeypatch.setattr(module.hashlib,'sha256',lambda value:calls.append(value))
    node = SafeReflector().reflect(b'x'*8192,InspectBudget(max_bytes=1024))
    assert node.kind=='opaque' and node.truncated and calls==[]


def test_weak_handle_expires_on_gc_and_other_sessions_cannot_resolve_it():
    class Value:
        pass
    reflector,other = SafeReflector(),SafeReflector()
    value = Value()
    reference = weakref.ref(value)
    handle = reflector.id_token(value)
    assert reflector.resolve(handle) is value and other.resolve(handle) is None
    assert other.id_token(value)!=handle
    del value
    gc.collect()
    assert reference() is None and reflector.resolve(handle) is None and not reflector._tokens
    fresh = Value()
    fresh_handle = reflector.id_token(fresh)
    reflector.clear()
    assert reflector.resolve(fresh_handle) is None and reflector.id_token(fresh)!=fresh_handle


@pytest.mark.parametrize('options', [dict(max_items=-1),dict(max_bytes=True),dict(max_depth=1000),
    dict(max_ms=51),dict(started_at=float('nan'))])
def test_invalid_inspection_budgets_are_refused(options):
    with pytest.raises(ValueError):
        InspectBudget(**options)
