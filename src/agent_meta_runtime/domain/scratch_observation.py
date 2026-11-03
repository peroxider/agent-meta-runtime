"""Secretless, bounded inspection of a trusted kernel namespace.

This mechanism supplies observations only. Root separately owns authorization,
source/Action provenance, durable bindings and expiration after worker loss.
"""
import itertools

from .canonical import canonical_json
from .reflection import InspectBudget,SafeReflector,exact_type_names,reflection_document

MAX_NAMESPACE_SCAN = 1000
MAX_BINDINGS = 100
MAX_OBSERVATION_BYTES = 1024*1024
_BUDGET_FIELDS = frozenset({'max_depth','max_items','max_bytes','max_ms'})


class ScratchObserver:
    def __init__(self):
        self.reflector = SafeReflector()
        self.busy = False
        self.cell_ordinal = 0
        self._before = {}
        self._metadata = {}
        self._generations = {}
        self.tracking_complete = True

    def begin_cell(self, namespace):
        self._before = {name:id(value) for name,value in self._bindings(namespace)[0]}

    def end_cell(self, namespace, writes=(), complete=True):
        self.cell_ordinal += 1
        pairs, truncated = self._bindings(namespace,writes)
        visible = {name for name,_ in pairs}
        self.tracking_complete = self.tracking_complete and complete and not truncated
        for name,value in pairs:
            changed = name in writes or name not in self._before or self._before[name] != id(value)
            if changed:
                if name not in self._generations and len(self._generations)>=4096:
                    self.tracking_complete = False
                    continue
                self._generations[name] = self._generations.get(name,0)+1
                previous = self._metadata.get(name)
                # The fixed bootstrap cell is not a user definition origin.
                created = previous['created_cell'] if previous and previous['created_cell']>1 else self.cell_ordinal
                self._metadata[name] = {'created_cell':created,'last_changed_cell':self.cell_ordinal,
                    'binding_generation':self._generations[name]}
        if not truncated:
            for name in tuple(self._metadata):
                if name not in visible:
                    del self._metadata[name]
        self._before.clear()

    def _bindings(self,namespace,written=()):
        if type(namespace) is not dict:
            raise ValueError('kernel namespace is unavailable')
        values = []
        scanned = 0
        for name,value in itertools.islice(dict.items(namespace),MAX_NAMESPACE_SCAN):
            scanned += 1
            if (type(name) is str and len(name)<=128 and name.isidentifier()
                    and (not name.startswith('_') or name in self._metadata or name in written)):
                values.append((name,value))
        values.sort(key=lambda pair:pair[0].encode('utf-8','replace'))
        return values[:MAX_BINDINGS],len(namespace)>scanned or len(values)>MAX_BINDINGS

    def _find(self,namespace,name):
        for key,value in itertools.islice(dict.items(namespace),MAX_NAMESPACE_SCAN):
            if type(key) is str and key==name:
                return value
        raise LookupError('binding is unavailable')

    def request(self,namespace,request):
        try:
            if self.busy:
                return {'error_code':'FAILED_PRECONDITION'}
            if type(request) is not dict or type(namespace) is not dict:
                raise ValueError('invalid observation request')
            operation = request.get('operation')
            if operation=='bindings' and set(request)=={'operation'}:
                pairs,truncated = self._bindings(namespace)
                entries = []
                for name,value in pairs:
                    module,kind = exact_type_names(value)
                    entries.append({'name':name,'type_module':module,'type_name':kind,
                        'handle':self.reflector.id_token(value),
                        'safe_summary':{'kind':'static-type','type_module':module,'type_name':kind,
                            **({'length':len(value)} if any(type(value) is kind for kind in (str,bytes,list,tuple,dict,set,frozenset)) else {})},
                        **self._metadata.get(name,{'created_cell':None,'last_changed_cell':None,'binding_generation':0})})
                result = {'cell_ordinal':self.cell_ordinal,'bindings':entries,'truncated':truncated,
                    'binding_write_tracking_complete':self.tracking_complete,
                    'binding_write_tracking_scope':'CELL_MAIN_THREAD','value_mutation_impact':'UNKNOWN_RISK'}
            elif operation=='inspect' and set(request) in ({'operation','name','budget'},{'operation','handle','budget'}):
                options = request['budget']
                if type(options) is not dict or not set(options)<=_BUDGET_FIELDS:
                    raise ValueError('invalid observation budget')
                budget = InspectBudget(**options)
                if 'name' in request:
                    name = request['name']
                    if type(name) is not str or not 1<=len(name)<=128 or not name.isidentifier():
                        raise ValueError('invalid binding identifier')
                    value = self._find(namespace,name)
                else:
                    handle = request['handle']
                    if type(handle) is not str or len(handle)>128:
                        raise ValueError('invalid observed handle')
                    value = self.reflector.resolve(handle)
                    if value is None:
                        return {'error_code':'HANDLE_EXPIRED'}
                result = {'cell_ordinal':self.cell_ordinal,'node':reflection_document(self.reflector.reflect(value,budget))}
            else:
                raise ValueError('unknown observation operation')
            encoded = canonical_json(result)
            if len(encoded)>MAX_OBSERVATION_BYTES:
                return {'error_code':'RESOURCE_EXHAUSTED'}
            return {'result':result}
        except LookupError:
            return {'error_code':'NOT_FOUND'}
        except (ValueError,TypeError,UnicodeError,RuntimeError):
            return {'error_code':'INVALID_ARGUMENT'}
