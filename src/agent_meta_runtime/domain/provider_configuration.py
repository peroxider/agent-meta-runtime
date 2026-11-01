"""Secretless signed Provider binding payload; shared SDK/enforcement checks."""

from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .ids import validate_id
from .provider_profile import valid_provider_handle


def configuration_payload(payload):
    fields={'harness_id','capability_id','profile_artifact_id','credential_handle','expected_configuration_revision','enabled'}
    try:
        if not isinstance(payload,dict) or set(payload)!=fields:
            raise ValueError('invalid fields')
        for key,scheme in (('harness_id','harness://'),('capability_id','capability://')):
            validate_id(payload[key])
            if not payload[key].startswith(scheme):
                raise ValueError('invalid identity scheme')
        if (not is_artifact_id(payload['profile_artifact_id']) or not valid_provider_handle(payload['credential_handle'])
                or type(payload['enabled']) is not bool or type(payload['expected_configuration_revision']) is not int
                or payload['expected_configuration_revision']<0):
            raise ValueError('invalid binding values')
    except (ValueError,TypeError,KeyError):
        raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider binding requires typed identities, a profile Artifact and an opaque native credential handle') from None
    return dict(payload)
