"""Scheduler/port regressions; these do not claim Backend isolation proof."""

import asyncio
from types import SimpleNamespace

import pytest

from agent_meta_runtime.application.task_host import TaskSession


def test_repeated_immediate_projections_allow_other_ready_work_before_more_commits():
    async def scenario():
        pulse_counts, commits = [], []
        projection = SimpleNamespace(manifest=SimpleNamespace(projection_id="fixed"))
        class Store:
            def check(self, task_id):
                pass
            def save_projection(self, task, request):
                commits.append(request)
                return projection
        session = TaskSession(Store(), SimpleNamespace(task_id="scheduler-port-fixture"), None)
        async def pulse():
            for _ in range(10):
                pulse_counts.append(len(commits))
                await asyncio.sleep(0)
        other = asyncio.create_task(pulse())
        for i in range(100):
            assert await session.project_context(i) is projection
        await other
        assert pulse_counts[0] == 0 and pulse_counts[-1] < 100
        assert len(set(pulse_counts)) > 1 and commits == list(range(100))
    asyncio.run(scenario())


@pytest.mark.parametrize("method", ["project_context", "invoke_model", "invoke_tool"])
def test_ready_cancellation_is_observed_before_any_facade_write_or_callback(method):
    async def scenario():
        cancelled = False
        class Store:
            def check(self, task_id):
                if cancelled:
                    raise asyncio.CancelledError()
            def __getattr__(self, name):
                raise AssertionError("cancelled facade performed store work")
        session = TaskSession(Store(), SimpleNamespace(task_id="scheduler-port-fixture"), None)
        async def cancel():
            nonlocal cancelled
            cancelled = True
        ready = asyncio.create_task(cancel())
        with pytest.raises(asyncio.CancelledError):
            await getattr(session, method)(None)
        await ready
        assert session._ordinal == session._models == 0 and not session._projections
    asyncio.run(scenario())
