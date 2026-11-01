"""Version-specific AMPAK module loading; public consumers use the bound Host."""

import asyncio
import sys

import pytest
from agent_meta_runtime.adapters.harness_loader import HarnessPackageLoader
from agent_meta_runtime.sdk import ErrorCode, StableError
from agent_meta_runtime.sdk.host import TaskBudget, TaskEnvelope, HealthProbeInvocation
from agent_meta_runtime.sdk.packages import PackageMeta, build_manifest, encode_package, sha256_hex


def task():
    content = b"input"
    surface = b"{}"
    return TaskEnvelope(
        "task://01900000-0000-7000-8000-000000000001", "realm://main",
        "principal://operator-root/01900000-0000-7000-8000-000000000002",
        "action://01900000-0000-7000-8000-000000000003",
        "artifact://sha256/" + sha256_hex(content), content,
        "composition://01900000-0000-7000-8000-000000000004", 1,
        "artifact://sha256/" + sha256_hex(surface), surface, (), TaskBudget(), 1, b"{}", None,
        b"{}", "artifact://sha256/" + sha256_hex(b"{}"), b"{}", b"{}",
    )


def package(value="one", factory=None):
    metadata = PackageMeta("example.harness", "0.1.0", "harness", "example.entry:create", None, None, (), (), {}, {}, None)
    files = {
        "example/__init__.py": b"",
        "example/helper.py": f"VALUE = {value!r}\n".encode(),
        "example/entry.py": (factory or """
from .helper import VALUE
from agent_meta_runtime.sdk.host import HarnessAdapter, HealthStatus, ModelResponse, TerminalResult, TextPart
async def run(task, host):
    return TerminalResult((TextPart(VALUE),))
async def model(request):
    return ModelResponse((TextPart(VALUE),), 'STOP')
async def probe(request):
    return HealthStatus('READY', 'OK')
def create():
    return HarnessAdapter(run, model, {}, probe)
""").encode(),
    }
    content = encode_package(build_manifest(metadata, files), files)
    return "artifact://sha256/" + sha256_hex(content), content


def test_two_versions_keep_distinct_relative_imports_and_never_scan_sys_path():
    first = HarnessPackageLoader(*package("one"))
    second = HarnessPackageLoader(*package("two"))
    previous_path = list(sys.path)
    try:
        one = first.instantiate(trust_class="builtin_or_signed", placement="in_process")
        two = second.instantiate(trust_class="builtin_or_signed", placement="in_process")
        probe = HealthProbeInvocation("request-1", "model", "capability://example.model", 1, "probe.model", 10_000_000)
        assert asyncio.run(one.probe(probe)).status == "READY"
        assert asyncio.run(one.run_task(task(), None)).parts[0].text == "one"
        assert asyncio.run(two.run_task(task(), None)).parts[0].text == "two"
        assert asyncio.run(one.run_task(task(), None)).parts[0].text == "one"
        assert first.namespace != second.namespace
        assert "example.entry" not in sys.modules
        assert list(sys.path) == previous_path
    finally:
        first.close()
        second.close()
    assert not any(name.startswith(first.namespace) or name.startswith(second.namespace) for name in sys.modules)


def test_untrusted_or_unsupported_placement_never_executes_package():
    loader = HarnessPackageLoader(*package(factory="raise SystemExit('should not execute')\n"))
    try:
        with pytest.raises(StableError) as error:
            loader.instantiate(trust_class="trusted_candidate", placement="in_process")
        assert error.value.code == ErrorCode.FEATURE_UNAVAILABLE
        assert not any(name.startswith(loader.namespace) for name in sys.modules)
    finally:
        loader.close()


def test_factory_failure_is_bounded_and_does_not_leak_raw_error():
    loader = HarnessPackageLoader(*package(factory="raise RuntimeError('sensitive test input')\n"))
    try:
        with pytest.raises(StableError) as error:
            loader.instantiate(trust_class="builtin_or_signed", placement="in_process")
        assert error.value.code == ErrorCode.INVALID_RESULT
        assert "sensitive" not in str(error.value.to_json())
    finally:
        loader.close()


def test_hash_tampering_and_drained_loader_are_rejected():
    identity, content = package()
    with pytest.raises(StableError) as error:
        HarnessPackageLoader(identity, content + b"x")
    assert error.value.code == ErrorCode.INTEGRITY_ERROR
    loader = HarnessPackageLoader(identity, content)
    loader.close()
    with pytest.raises(StableError) as error:
        loader.instantiate(trust_class="builtin_or_signed", placement="in_process")
    assert error.value.code == ErrorCode.FAILED_PRECONDITION


@pytest.mark.parametrize("factory", [
    "from agent_meta_runtime.sdk import StableError, ErrorCode\ndef create():\n    raise StableError(code=ErrorCode.INTERNAL, message='credential-canary', details={'raw': 'credential-canary'})\n",
    "async def create():\n    raise RuntimeError('credential-canary')\n",
])
def test_factory_errors_and_async_factories_cannot_leak_payloads(factory, recwarn):
    import gc
    loader = HarnessPackageLoader(*package(factory=factory))
    try:
        with pytest.raises(StableError) as invalid:
            loader.instantiate(trust_class="builtin_or_signed", placement="in_process")
        assert invalid.value.code == ErrorCode.INVALID_RESULT
        assert "credential-canary" not in str(invalid.value.to_json())
        gc.collect()
        assert not [warning for warning in recwarn if issubclass(warning.category, RuntimeWarning)]
    finally:
        loader.close()
