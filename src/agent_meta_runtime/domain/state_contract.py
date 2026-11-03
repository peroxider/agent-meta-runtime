"""Exact public managed-State payloads; all I/O/authority remains in Runtime."""
from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .ids import validate_id

PURPOSES = frozenset({'GENERAL', 'SESSION_TRANSCRIPT', 'SESSION_JOURNAL'})


def _invalid():
    return StableError(code=ErrorCode.INVALID_ARGUMENT, message='invalid managed State payload')


def _identity(value, prefix):
    try:
        if not isinstance(value, str) or not value.startswith(prefix) or len(value)>1024:
            raise ValueError('invalid State identity')
        validate_id(value)
    except (ValueError, TypeError):
        raise _invalid() from None


def state_payload(payload_type, value):
    shapes = {
        'state.create/v1': ({'state_id','owner_id','schema_id','content_artifact_id'}, {'purpose','redaction_policy_artifact_id'}),
        'state.read/v1': ({'state_id'}, {'state_revision_id'}),
        'state.write/v1': ({'state_id','expected_state_revision_id','expected_cas_revision','schema_id','content_artifact_id'}, set()),
    }
    if payload_type not in shapes or not isinstance(value, dict):
        raise _invalid()
    required, optional = shapes[payload_type]
    if not required<=set(value) or set(value)-required-optional:
        raise _invalid()
    _identity(value['state_id'], 'state://')
    for field in ('state_revision_id','expected_state_revision_id'):
        if field in value:
            _identity(value[field], 'state-revision://')
    for field in ('schema_id','content_artifact_id','redaction_policy_artifact_id'):
        if field in value and not is_artifact_id(value[field]):
            raise _invalid()
    if 'owner_id' in value:
        owner = value['owner_id']
        if not isinstance(owner, str) or not owner.startswith(('capability://','composition://')):
            raise _invalid()
        _identity(owner, owner.split('://',1)[0]+'://')
    if 'purpose' in value and (not isinstance(value['purpose'],str) or value['purpose'] not in PURPOSES):
        raise _invalid()
    if 'expected_cas_revision' in value and (type(value['expected_cas_revision']) is not int or not 1<=value['expected_cas_revision']<=2**53-1):
        raise _invalid()
    return dict(value)
