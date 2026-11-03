"""Secretless plans and bounded receipts for Task-scoped Meta resources.

    Requests express intent only. Only the Runtime may publish content, move a
    State head, or commit the corresponding Invocation. No native access crosses
    this boundary (ADR 060).
"""

from dataclasses import dataclass
import re
from typing import Callable

from .canonical import sha256_hex
from .harness import is_artifact_id
from .ids import validate_id
from .scratch_execution import ScratchCreate, ScratchExecution, ScratchRelease, is_scratch_request

MAX_RESOURCE_CONTENT_BYTES = 1024 * 1024
RESOURCE_OPERATION_RULES = {
    'artifact.read/v1': ('PURE', frozenset({'none'}), frozenset()),
    'artifact.put/v1': ('KEYED', frozenset({'artifact.put'}), frozenset({'artifact.put'})),
    'state.read/v1': ('PURE', frozenset({'state.read'}), frozenset({'state.read'})),
    'state.write/v1': ('KEYED', frozenset({'state.write'}), frozenset({'state.write'})),
    'scratch.create/v1': ('KEYED', frozenset({'process.spawn'}), frozenset({'scratch.create', 'scratch.execute'})),
    'scratch.execute/v1': ('KEYED', frozenset({'external.irreversible'}), frozenset({'scratch.execute'})),
    'scratch.release/v1': ('KEYED', frozenset({'external.irreversible'}), frozenset({'scratch.release'})),
    'scratch.bindings/v1': ('PURE', frozenset({'none'}), frozenset({'scratch.inspect'})),
    'scratch.inspect/v1': ('PURE', frozenset({'none'}), frozenset({'scratch.inspect'})),
    'scratch.export/v1': ('KEYED', frozenset({'artifact.put'}), frozenset({'scratch.export', 'artifact.put'})),
}
RESOURCE_CONTRACTS = frozenset(RESOURCE_OPERATION_RULES)


def validate_resource_operation(operation):
    contract = operation.get('resource_contract')
    if contract is None:
        return
    if not isinstance(contract, str) or contract not in RESOURCE_OPERATION_RULES:
        raise ValueError('unknown resource operation contract')
    idem, effects, permissions = RESOURCE_OPERATION_RULES[contract]
    if (operation.get('idempotency') != idem or set(operation.get('effects', ())) != effects
            or not permissions <= set(operation.get('required_permissions', ()))):
        raise ValueError('resource operation effects, permissions or idempotency differ')


def _id(value, prefix):
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError('invalid resource identity')
    validate_id(value)


def _bytes(value):
    if type(value) is not bytes or len(value) > MAX_RESOURCE_CONTENT_BYTES:
        raise ValueError('resource content must be bounded immutable bytes')


@dataclass(frozen=True, slots=True)
class ArtifactRead:
    artifact_id: str

    def __post_init__(self):
        if not is_artifact_id(self.artifact_id):
            raise ValueError('invalid Artifact reference')


@dataclass(frozen=True, slots=True)
class ArtifactPut:
    kind: str
    media_type: str
    content: bytes

    def __post_init__(self):
        if not isinstance(self.kind, str) or re.fullmatch(r'[a-z][a-z0-9_]{0,63}', self.kind) is None:
            raise ValueError('invalid Artifact kind')
        if self.media_type not in ('application/json', 'text/plain; charset=utf-8'):
            raise ValueError('resource writes require JSON or UTF-8 text')
        _bytes(self.content)


@dataclass(frozen=True, slots=True)
class StateRead:
    state_id: str

    def __post_init__(self):
        _id(self.state_id, 'state://')


@dataclass(frozen=True, slots=True)
class StateWrite:
    state_id: str
    expected_state_revision_id: str
    content_artifact_id: str

    def __post_init__(self):
        _id(self.state_id, 'state://')
        _id(self.expected_state_revision_id, 'state-revision://')
        if not is_artifact_id(self.content_artifact_id):
            raise ValueError('invalid State content reference')


def resource_request_document(request):
    """Persist hashes/identities, never raw proposed Artifact bytes."""
    if is_scratch_request(request):
        return request.document()
    if type(request) is ArtifactRead:
        return {'schema': 'artifact.read/v1', 'artifact_id': request.artifact_id}
    if type(request) is ArtifactPut:
        return {'schema': 'artifact.put/v1', 'kind': request.kind, 'media_type': request.media_type,
            'content_sha256': sha256_hex(request.content), 'size_bytes': len(request.content)}
    if type(request) is StateRead:
        return {'schema': 'state.read/v1', 'state_id': request.state_id}
    if type(request) is StateWrite:
        return {'schema': 'state.write/v1', 'state_id': request.state_id,
            'expected_state_revision_id': request.expected_state_revision_id, 'content_artifact_id': request.content_artifact_id}
    raise ValueError('unknown resource request')


@dataclass(frozen=True, slots=True)
class ResourceReceipt:
    contract: str
    artifact_id: str
    media_type: str
    content: bytes
    state_id: str | None = None
    state_revision_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.contract, str) or self.contract not in RESOURCE_CONTRACTS or not is_artifact_id(self.artifact_id):
            raise ValueError('invalid resource receipt')
        _bytes(self.content)
        if self.artifact_id != 'artifact://sha256/' + sha256_hex(self.content):
            raise ValueError('resource content differs from its Artifact reference')
        if not isinstance(self.media_type, str) or not 1 <= len(self.media_type) <= 128:
            raise ValueError('invalid resource media type')
        if self.contract.startswith('state.'):
            _id(self.state_id, 'state://')
            _id(self.state_revision_id, 'state-revision://')
        elif self.state_id is not None or self.state_revision_id is not None:
            raise ValueError('Artifact receipt cannot contain State bindings')


@dataclass(frozen=True, slots=True)
class ResourceAdapter:
    """Pure synchronous planning/normalization; Runtime owns every mutation."""
    prepare: Callable
    normalize: Callable

    def __post_init__(self):
        if not callable(self.prepare) or not callable(self.normalize):
            raise ValueError('resource adapter requires plan and normalization callbacks')
