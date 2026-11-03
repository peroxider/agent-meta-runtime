"""Kernel observations carry bounded metadata and weak handles, never values."""
import gc

from agent_meta_runtime.domain.scratch_observation import ScratchObserver


def test_bindings_list_exact_types_without_rendering_values_or_descriptors():
    calls = []
    class Meta(type):
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError('metaclass lookup')
    class Value(metaclass=Meta):
        def __repr__(self):
            calls.append('repr')
            raise AssertionError('repr')
    observer = ScratchObserver()
    secret = 'SCRATCH_BINDING_VALUE_CANARY_7dfba09a'
    result = observer.request({'value':Value(),'number':42,'secret':secret}, {'operation':'bindings'})['result']
    assert [entry['name'] for entry in result['bindings']]==['number','secret','value']
    assert result['bindings'][0]['handle'] is None
    assert result['bindings'][2]['type_name']=='Value' and calls==[]
    assert secret not in str(result)


def test_observed_handles_do_not_keep_deleted_values_alive():
    class Value:
        pass
    observer = ScratchObserver()
    namespace = {'value':Value()}
    handle = observer.request(namespace,{'operation':'bindings'})['result']['bindings'][0]['handle']
    response = observer.request(namespace,{'operation':'inspect','handle':handle,'budget':{}})
    assert response['result']['node']['kind']=='object'
    namespace.clear()
    gc.collect()
    assert observer.request(namespace,{'operation':'inspect','handle':handle,'budget':{}})=={'error_code':'HANDLE_EXPIRED'}


def test_namespace_and_output_inventory_are_bounded_explicitly():
    observer = ScratchObserver()
    result = observer.request({f'value_{index}':index for index in range(10000)}, {'operation':'bindings'})['result']
    assert result['truncated'] and len(result['bindings'])==100


def test_busy_unknown_and_non_identifier_requests_fail_closed():
    observer = ScratchObserver()
    observer.busy = True
    assert observer.request({}, {'operation':'bindings'})=={'error_code':'FAILED_PRECONDITION'}
    observer.busy = False
    for request in ({'operation':'execute'},{'operation':'inspect','name':'x.y','budget':{}},
            {'operation':'inspect','name':'value','budget':{'max_items':10001}},
            {'operation':'inspect','name':'value','budget':{'started_at':0}}):
        assert observer.request({},request)=={'error_code':'INVALID_ARGUMENT'}
    assert observer.request({}, {'operation':'inspect','name':'missing','budget':{}})=={'error_code':'NOT_FOUND'}
