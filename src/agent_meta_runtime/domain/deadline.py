"""Deadline and cancellation primitives (Step 00, item 3).

Deadlines are integer microsecond budgets measured against the monotonic
clock so they are immune to wall-clock jumps; cancellation is cooperative and
propagates ``CancellationError`` at await/check points only.
"""

from __future__ import annotations

import asyncio
import time

__all__ = ["CancellationError", "CancellationToken", "Deadline", "DeadlineExceeded"]


class DeadlineExceeded(Exception):
    """The operation's deadline elapsed before completion."""


class CancellationError(Exception):
    """The operation was cooperatively cancelled."""


class Deadline:
    """An absolute budget on the monotonic clock, in microseconds."""

    __slots__ = ("_at_monotonic_us",)

    def __init__(self, at_monotonic_us: int) -> None:
        self._at_monotonic_us = at_monotonic_us

    @classmethod
    def after(cls, duration_us: int) -> "Deadline":
        if not isinstance(duration_us, int) or duration_us < 0:
            raise ValueError("duration must be a non-negative integer of microseconds")
        return cls(time.monotonic_ns() // 1_000 + duration_us)

    @classmethod
    def never(cls) -> "Deadline":
        return cls(1 << 62)

    @property
    def remaining_us(self) -> int:
        return max(0, self._at_monotonic_us - time.monotonic_ns() // 1_000)

    @property
    def expired(self) -> bool:
        return self.remaining_us == 0

    def check(self) -> None:
        if self.expired:
            raise DeadlineExceeded("deadline exceeded")

    async def sleep(self, delay_us: int) -> None:
        """Sleep bounded by the deadline; raises DeadlineExceeded on overrun."""

        self.check()
        budget_s = self.remaining_us / 1_000_000
        await asyncio.sleep(min(delay_us / 1_000_000, budget_s))
        self.check()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Deadline(remaining_us={self.remaining_us})"


class CancellationToken:
    """Cooperative cancellation token with parent -> child cascade."""

    __slots__ = ("_cancelled", "_reason", "_children")

    def __init__(self) -> None:
        self._cancelled = False
        self._reason: str | None = None
        self._children: list["CancellationToken"] = []

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def reason(self) -> str | None:
        return self._reason

    def cancel(self, reason: str | None = None) -> None:
        if self._cancelled:
            return
        self._cancelled = True
        self._reason = reason
        for child in self._children:
            child.cancel(reason)

    def check(self) -> None:
        if self._cancelled:
            raise CancellationError(self._reason or "cancelled")

    async def wait(self) -> None:
        """Await until cancelled; raises immediately if already cancelled."""

        while not self._cancelled:
            await asyncio.sleep(0.05)
        raise CancellationError(self._reason or "cancelled")

    def child(self) -> "CancellationToken":
        """A token that is cancelled together with this one."""

        token = CancellationToken()
        if self._cancelled:
            token.cancel(self._reason)
        self._children.append(token)
        return token
