"""Pure allocation/closed metadata checks; synthetic counter is not GLM proof."""
from dataclasses import replace
import json
from unittest.mock import patch

import pytest

from agent_meta_runtime.adapters.context_tokenizer import load_glm53_context_tokenizer
from agent_meta_runtime.domain.context_tokenizer import context_tokenizer_descriptor
from agent_meta_runtime.sdk import ErrorCode, StableError
from agent_meta_runtime.sdk.context import build_projection_input, glm53_context_tokenizer_descriptor, rendered_sections
from agent_meta_runtime.sdk.host import ContextProjection, ProjectionManifest, Section
from agent_meta_runtime.sdk.packages import canonical_json
from test_context_contract import task_fixture, ref, section_json


def pairs(content):
    # An explicit synthetic subword-like counter, not an installed native engine.
    return (len(content.decode('utf-8'))+1)//2


def test_native_descriptor_does_not_implicitly_use_bytes_when_engine_missing():
    task=task_fixture(tokenizer_descriptor=glm53_context_tokenizer_descriptor())
    with pytest.raises(StableError) as error:
        build_projection_input(task)
    assert error.value.code==ErrorCode.FAILED_PRECONDITION


@pytest.mark.parametrize('change',[
    {'vocabulary_sha256':'0'*64},{'vocabulary_bytes':True},{'engine_version':'0.23.4'},
    {'algorithm':'DOWNLOAD_FROM_URL'},{'model_id':'different'},{'unknown':'forbidden'},
])
def test_native_identity_is_closed_before_any_implementation_can_be_selected(change):
    with pytest.raises(StableError):
        context_tokenizer_descriptor({**glm53_context_tokenizer_descriptor(),**change})


@pytest.mark.parametrize('value',[True,-1,2**53,None])
def test_bad_counter_results_fail_closed(value):
    task=task_fixture(tokenizer_descriptor=glm53_context_tokenizer_descriptor())
    with pytest.raises(StableError):
        build_projection_input(task,token_counter=lambda _:value)


def test_native_counting_uses_redacted_data_and_measures_complete_prefixes():
    calls=[]
    def counter(content):
        calls.append(content)
        return pairs(content)
    task=task_fixture(value={'value':'你好，世界','password':'UNREDACTED_CONTEXT_CANARY'},
        tokenizer_descriptor=glm53_context_tokenizer_descriptor())
    value=build_projection_input(task,token_counter=counter)
    assert value==build_projection_input(task,token_counter=counter)
    assert all(section.token_count==pairs(section.content) for section in value.sections)
    assert any(section.token_count!=len(section.content) for section in value.sections)
    assert not any(b'UNREDACTED_CONTEXT_CANARY' in raw for raw in calls)
    assert section_json(value,'task_input')=={'value':'你好，世界','password':'[REDACTED]'}
    assert any(b'\n\x1e\n' in raw for raw in calls)


def test_native_tail_truncation_returns_a_measured_valid_unicode_prefix():
    original='你好世界'*500
    task=task_fixture(value={'value':original},budget=512,overflow='TAIL_TRUNCATE',
        tokenizer_descriptor=glm53_context_tokenizer_descriptor())
    value=build_projection_input(task,token_counter=pairs)
    text=section_json(value,'task_input')['value']
    assert 0<len(text)<len(original) and original.startswith(text)
    assert pairs(b'\n\x1e\n'.join(section.content for section in value.sections))<=512


@pytest.mark.parametrize('raw',[b'',b'invalid',bytearray(b'mutable'),None])
def test_unverified_native_data_never_loads_optional_code(raw):
    with patch('importlib.metadata.version') as version:
        with pytest.raises(StableError) as error:
            load_glm53_context_tokenizer(raw)
        assert error.value.code==ErrorCode.INTEGRITY_ERROR
        version.assert_not_called()
