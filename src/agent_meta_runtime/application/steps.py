"""Drive one orchestration program with synchronous or asynchronous effects.

Only Runtime services construct these private steps. They are not a persistence
format or a Harness facade; semantic transactions stay in the calling program.
"""

import asyncio
from dataclasses import dataclass, field
import inspect
import time
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class Call:
    callback: Callable
    args: tuple = ()
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    timeout_s: float | None = None


def drive(program, *, before_call=lambda: None):
    value, error = None, None
    try:
        while True:
            try:
                step = program.throw(error) if error is not None else program.send(value)
            except StopIteration as finished:
                return finished.value
            value, error = None, None
            try:
                before_call()
                started = time.perf_counter()
                value = step.callback(*step.args, **step.kwargs)
                if inspect.isawaitable(value):
                    if inspect.iscoroutine(value):
                        value.close()
                    raise TypeError("async callback requires the asynchronous service entry point")
                if step.timeout_s is not None and time.perf_counter() - started >= step.timeout_s:
                    raise TimeoutError("external result arrived after its deadline")
            except BaseException as failure:
                error = failure
    finally:
        program.close()


async def drive_async(program, *, before_call=lambda: None):
    value, error = None, None
    try:
        while True:
            try:
                step = program.throw(error) if error is not None else program.send(value)
            except StopIteration as finished:
                return finished.value
            value, error = None, None
            try:
                before_call()
                started = time.perf_counter()
                value = step.callback(*step.args, **step.kwargs)
                if inspect.isawaitable(value):
                    if step.timeout_s is None:
                        value = await value
                    else:
                        async with asyncio.timeout(step.timeout_s) as deadline:
                            value = await value
                        if deadline.expired():
                            raise TimeoutError("external callback suppressed deadline cancellation")
                if step.timeout_s is not None and time.perf_counter() - started >= step.timeout_s:
                    raise TimeoutError("external result arrived after its deadline")
            except BaseException as failure:
                error = failure
    finally:
        program.close()
