"""Bounded output values for the independent trusted Scratch worker.

These are process mechanisms, not a sandbox or an admission/Authority API.
"""
from dataclasses import dataclass
import math
import re

from .canonical import canonical_json

CHANNEL_LIMIT_BYTES = 1024 * 1024
MAX_CELL_BYTES = 1024 * 1024
MAX_DISPLAY_MESSAGES = 64
TRUNCATED = '\n...[truncated]'
MIME_TYPES = frozenset({'text/plain','text/html','image/png','image/jpeg','image/svg+xml','application/json'})


def utf8_prefix(value, limit):
    """Never allocate an encoding proportional to an unbounded input string."""
    piece = value[:limit+1]
    raw = piece.encode('utf-8',errors='replace')
    if len(raw)>limit:
        return raw[:limit].decode('utf-8',errors='ignore'), True
    return raw.decode('utf-8'), len(piece)<len(value)


def _json_value(value, remaining, depth=0, counter=None):
    if counter is None:
        counter = [0,remaining]
    counter[0] += 1
    if counter[0]>8192 or depth>32 or counter[1]<0:
        raise ValueError('display JSON structure exceeds ceiling')
    kind = type(value)
    if value is None or kind is bool:
        counter[1] -= 5
        return value
    if kind is int and abs(value)<=2**53-1:
        counter[1] -= len(str(value))
        return value
    if kind is float and math.isfinite(value):
        counter[1] -= len(canonical_json(value))
        return value
    if kind is str:
        text, cut = utf8_prefix(value,max(0,counter[1]))
        size = len(canonical_json(text))
        if cut or size>counter[1]:
            raise ValueError('display JSON text exceeds ceiling')
        counter[1] -= size
        return text
    if kind is list and len(value)<=8192:
        counter[1] -= len(value)+2
        return [_json_value(item,remaining,depth+1,counter) for item in value]
    if kind is dict and len(value)<=8192 and all(type(key) is str for key in value):
        counter[1] -= len(value)*2+2
        result = {}
        for key,item in value.items():
            safe_key = _json_value(key,remaining,depth+1,counter)
            result[safe_key] = _json_value(item,remaining,depth+1,counter)
        return result
    raise ValueError('unsupported display JSON value')


class CellOutputBudget:
    """One cell's independent stream/display byte ceilings, before publication."""
    def __init__(self, limit=CHANNEL_LIMIT_BYTES):
        if type(limit) is not int or not 64<=limit<=CHANNEL_LIMIT_BYTES:
            raise ValueError('invalid channel ceiling')
        self.limit = limit
        self.used = {'stdout':0,'stderr':0,'display':0}
        self.truncated = {'stdout':False,'stderr':False,'display':False}
        self.display_count = 0

    def stream(self, channel, text):
        if channel not in ('stdout','stderr') or type(text) is not str:
            raise ValueError('invalid stream value')
        if self.truncated[channel]:
            return ''
        remaining = self.limit-self.used[channel]
        value, cut = utf8_prefix(text,remaining)
        if cut:
            self.truncated[channel] = True
            if remaining>=len(TRUNCATED):
                value = utf8_prefix(text,remaining-len(TRUNCATED))[0]+TRUNCATED
        self.used[channel] += len(value.encode('utf-8'))
        return value

    def display(self, content):
        remaining = self.limit-self.used['display']
        if type(content) is not dict or type(content.get('data')) is not dict or len(content['data'])>16 or self.display_count>=MAX_DISPLAY_MESSAGES or remaining<64:
            self.truncated['display'] = True
            return None
        data = {}
        for mime,value in content['data'].items():
            if type(mime) is not str or mime not in MIME_TYPES:
                self.truncated['display'] = True
                continue
            try:
                candidate = {**data,mime:_json_value(value,remaining)}
                raw = canonical_json({'data':candidate,'metadata':{}})
                if len(raw)>remaining:
                    raise ValueError('display bundle exceeds remaining ceiling')
                data = candidate
            except (ValueError,TypeError,UnicodeError,RecursionError):
                self.truncated['display'] = True
        if not data:
            if not self.truncated['display']:
                return None
            data = {'text/plain':'[display truncated]'}
        bundle = {'data':data,'metadata':{}}
        raw = canonical_json(bundle)
        if len(raw)>remaining:
            self.truncated['display'] = True
            return None
        self.used['display'] += len(raw)
        self.display_count += 1
        return bundle

    def flags(self):
        return {name+'_truncated':value for name,value in self.truncated.items()}


@dataclass(frozen=True,slots=True)
class ScratchCellResult:
    ordinal: int
    execution_count: int
    stdout: str
    stderr: str
    displays: tuple[bytes,...]
    stdout_truncated: bool
    stderr_truncated: bool
    display_truncated: bool
    error_type: str | None = None

    def __post_init__(self):
        if type(self.ordinal) is not int or self.ordinal<1 or type(self.execution_count) is not int or self.execution_count<0:
            raise ValueError('invalid Scratch execution identity')
        for value in (self.stdout,self.stderr):
            if type(value) is not str or len(value.encode('utf-8'))>CHANNEL_LIMIT_BYTES:
                raise ValueError('invalid bounded stream result')
        if type(self.displays) is not tuple or len(self.displays)>MAX_DISPLAY_MESSAGES or any(type(value) is not bytes for value in self.displays) or sum(map(len,self.displays))>CHANNEL_LIMIT_BYTES:
            raise ValueError('invalid bounded display result')
        if any(type(value) is not bool for value in (self.stdout_truncated,self.stderr_truncated,self.display_truncated)):
            raise ValueError('invalid truncation flags')
        if self.error_type is not None and (type(self.error_type) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',self.error_type) is None):
            raise ValueError('invalid sanitized error type')
