"""Pure per-cell producer/receiver bounds, including hostile value shapes."""
import json

import pytest

from agent_meta_runtime.domain.scratch_worker import CellOutputBudget, ScratchCellResult


def test_stream_limits_are_independent_utf8_safe_and_count_all_writes():
    budget = CellOutputBudget(64)
    first = budget.stream('stdout','é'*20)
    second = budget.stream('stdout','é'*40)
    assert len((first+second).encode())<=64 and budget.flags()['stdout_truncated']
    assert budget.stream('stderr','separate')=='separate'
    assert not budget.flags()['stderr_truncated']
    assert budget.stream('stdout','ignored')==''


def test_display_limits_include_metadata_wrappers_and_multiple_messages():
    budget = CellOutputBudget(128)
    first = budget.display({'data':{'text/plain':'small'},'metadata':{'secret':'not forwarded'}})
    assert first=={'data':{'text/plain':'small'},'metadata':{}}
    for _ in range(100):
        result = budget.display({'data':{'image/png':'A'*1000}})
        if result:
            assert len(json.dumps(result).encode())<128
    assert budget.used['display']<=128 and budget.flags()['display_truncated']


@pytest.mark.parametrize('value', [float('nan'),float('inf'),2**53,object(),['x'*1000]*1000,{'k'*1000:'v'},[[[[[None]]]]]*9000])
def test_display_values_outside_the_bounded_json_contract_are_not_published(value):
    budget = CellOutputBudget(128)
    result = budget.display({'data':{'application/json':value}})
    assert budget.flags()['display_truncated']
    assert result is None or result=={'data':{'text/plain':'[display truncated]'},'metadata':{}}


def test_result_has_immutable_bounded_display_and_sanitized_error():
    good = dict(ordinal=1,execution_count=1,stdout='',stderr='',displays=(),stdout_truncated=False,
        stderr_truncated=False,display_truncated=False,error_type=None)
    assert ScratchCellResult(**good).ordinal==1
    for override in ({'ordinal':True},{'displays':[]},{'stdout_truncated':1},{'error_type':'secret: raw exception'}):
        with pytest.raises(ValueError):
            ScratchCellResult(**{**good,**override})
