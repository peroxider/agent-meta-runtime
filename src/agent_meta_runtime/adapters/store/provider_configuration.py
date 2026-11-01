"""Operator-approved installation/profile/credential binding as immutable Fact."""

from dataclasses import dataclass
import json

from ...domain.errors import ErrorCode, StableError
from ...domain.fact_catalog import validate_fact_event
from ...domain.harness import is_artifact_id
from ...domain.ids import validate_id
from ...domain.provider_configuration import configuration_payload
from ...domain.provider_profile import valid_provider_handle
from ...ports.repositories import FactAppendRequest

_FIELDS = {'schema','harness_id','package_artifact_id','capability_id','profile_artifact_id','credential_handle',
    'enabled','configuration_revision','epoch_id','verified_artifact_ids'}


def provider_configuration(conn, realm_id, harness_id):
    row = conn.execute("SELECT fact_id,payload_json FROM facts WHERE realm_id=? AND entity_id=? AND event_type='provider_configured' ORDER BY seq DESC LIMIT 1", (realm_id,harness_id)).fetchone()
    if row is None:
        return None
    return _configuration(row, harness_id)


def provider_configuration_at(conn, realm_id, fact_id):
    row = conn.execute("SELECT fact_id,payload_json,entity_id FROM facts WHERE realm_id=? AND fact_id=? AND entity_type='harness' AND event_type='provider_configured'", (realm_id,fact_id)).fetchone()
    if row is None:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='frozen Provider approval is unavailable')
    return _configuration(row[:2], row[2])


def _configuration(row, harness_id):
    try:
        value=json.loads(row[1])
        if (not isinstance(value,dict) or set(value)!=_FIELDS or value['schema']!='harness-provider-configuration/v1' or value['harness_id']!=harness_id
                or type(value['configuration_revision']) is not int or value['configuration_revision']<1
                or type(value['enabled']) is not bool or not valid_provider_handle(value['credential_handle'])
                or not is_artifact_id(value['profile_artifact_id']) or not is_artifact_id(value['package_artifact_id'])
                or not isinstance(value['verified_artifact_ids'],list) or not all(is_artifact_id(ref) for ref in value['verified_artifact_ids'])
                or value['verified_artifact_ids']!=sorted(set(value['verified_artifact_ids']))
                or value['profile_artifact_id'] not in value['verified_artifact_ids']):
            raise ValueError('invalid binding')
        for key,scheme in (('harness_id','harness://'),('capability_id','capability://'),('epoch_id','epoch://')):
            validate_id(value[key])
            if not value[key].startswith(scheme):
                raise ValueError('invalid binding identity')
    except (ValueError,TypeError,KeyError,StableError):
        raise StableError(code=ErrorCode.INTEGRITY_ERROR,message='invalid Provider configuration Fact') from None
    return {**value,'configuration_fact_id':row[0]}


@dataclass(frozen=True, slots=True)
class ConfigureProviderRequest:
    realm_id: str
    harness_id: str
    package_artifact_id: str
    capability_id: str
    profile_artifact_id: str
    credential_handle: str
    expected_configuration_revision: int
    enabled: bool
    verified_artifact_ids: tuple[str,...]

    def __post_init__(self):
        configuration_payload({'harness_id':self.harness_id,'capability_id':self.capability_id,'profile_artifact_id':self.profile_artifact_id,
            'credential_handle':self.credential_handle,'expected_configuration_revision':self.expected_configuration_revision,'enabled':self.enabled})
        for value,scheme in ((self.realm_id,'realm://'),(self.harness_id,'harness://'),(self.capability_id,'capability://')):
            validate_id(value)
            if not value.startswith(scheme):
                raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='Provider configuration identity has the wrong scheme')
        if (not is_artifact_id(self.package_artifact_id) or not is_artifact_id(self.profile_artifact_id)
                or not valid_provider_handle(self.credential_handle)
                or type(self.expected_configuration_revision) is not int or self.expected_configuration_revision<0
                or type(self.enabled) is not bool or not self.verified_artifact_ids
                or any(not is_artifact_id(ref) for ref in self.verified_artifact_ids)
                or self.profile_artifact_id not in self.verified_artifact_ids):
            raise StableError(code=ErrorCode.INVALID_ARGUMENT,message='invalid Provider configuration request')
        object.__setattr__(self,'verified_artifact_ids',tuple(sorted(set(self.verified_artifact_ids))))


def configure_provider(request):
    def configure(txn):
        if txn._envelope.realm_id!=request.realm_id or txn._envelope.expected_meta_revision is None:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider configuration requires a signed Realm revision guard')
        epoch=txn._conn.execute('SELECT e.epoch_id,e.authority_root_principal_id FROM realms r JOIN epochs e ON e.epoch_id=r.epoch_id AND e.realm_id=r.realm_id WHERE r.realm_id=?',(request.realm_id,)).fetchone()
        if epoch is None or txn._envelope.actor_id!=epoch[1]:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED,message='Provider credential binding requires the current Root operator')
        installation=txn._conn.execute('SELECT realm_id,package_artifact_id,status FROM harness_installations WHERE harness_id=?',(request.harness_id,)).fetchone()
        if installation is None or installation[0]!=request.realm_id:
            raise StableError(code=ErrorCode.NOT_FOUND,message='Provider configuration installation is unavailable')
        if installation[1]!=request.package_artifact_id or installation[2]=='UNINSTALLED':
            raise StableError(code=ErrorCode.FAILED_PRECONDITION,message='Provider configuration installation differs or is uninstalled')
        old=provider_configuration(txn._conn,request.realm_id,request.harness_id)
        if request.expected_configuration_revision!=(old['configuration_revision'] if old else 0):
            raise StableError(code=ErrorCode.REVISION_CONFLICT,message='Provider configuration revision changed')
        payload={'schema':'harness-provider-configuration/v1','harness_id':request.harness_id,'package_artifact_id':request.package_artifact_id,
            'capability_id':request.capability_id,'profile_artifact_id':request.profile_artifact_id,'credential_handle':request.credential_handle,
            'enabled':request.enabled,'configuration_revision':request.expected_configuration_revision+1,'epoch_id':epoch[0],
            'verified_artifact_ids':sorted(set(request.verified_artifact_ids))}
        validate_fact_event('harness','provider_configured',1,payload)
        fact=txn.append_fact(FactAppendRequest(entity_type='harness',entity_id=request.harness_id,event_type='provider_configured',
            schema_version=1,payload=payload,actor_id=txn._envelope.actor_id,occurred_at_us=txn.recorded_at_us))
        return {'harness_id':request.harness_id,'configuration_fact_id':fact,'configuration_revision':payload['configuration_revision']}
    return configure
