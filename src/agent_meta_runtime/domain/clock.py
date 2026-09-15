"""Clock stability monitoring for lease scheduling (§41.59.4).

Lease deadlines inside one daemon process are scheduled on the monotonic
clock; wall UTC microseconds are persisted only for cross-process takeover.
Every 10 seconds the monitor compares the wall delta against the monotonic
delta: an absolute difference above 5 seconds sets ``CLOCK_UNSTABLE``,
readiness false, and stops new lease acquisition. Already-held leases may
still complete or be abandoned as PENDING within this process's monotonic
deadline — never extended because of rolled-back wall time. Recovery is
automatic after 3 consecutive checks 10 seconds apart with a difference of
at most 1 second. Forward wall jumps never preempt a lease whose monotonic
deadline has not passed (no other process can exist alongside the daemon
lock).
"""

from __future__ import annotations

import time
from typing import Callable

__all__ = ["ClockStabilityMonitor", "CLOCK_UNSTABLE_REASON"]

CLOCK_UNSTABLE_REASON = "CLOCK_UNSTABLE"

_CHECK_INTERVAL_S = 10.0
_UNSTABLE_TOLERANCE_S = 5.0
_RECOVERY_TOLERANCE_S = 1.0
_RECOVERY_STREAK = 3


class ClockStabilityMonitor:
    """Detects wall/monotonic divergence on a 10-second cadence."""

    def __init__(
        self,
        *,
        check_interval_s: float = _CHECK_INTERVAL_S,
        unstable_tolerance_s: float = _UNSTABLE_TOLERANCE_S,
        recovery_tolerance_s: float = _RECOVERY_TOLERANCE_S,
        recovery_streak: int = _RECOVERY_STREAK,
        monotonic: Callable[[], float] | None = None,
        wall: Callable[[], float] | None = None,
    ) -> None:
        self._check_interval_s = check_interval_s
        self._unstable_tolerance_s = unstable_tolerance_s
        self._recovery_tolerance_s = recovery_tolerance_s
        self._recovery_streak = recovery_streak
        self._monotonic = monotonic or time.monotonic
        self._wall = wall or time.time
        self._last_monotonic = self._monotonic()
        self._last_wall = self._wall()
        self._stable_streak = 0
        self.unstable = False
        self.last_delta_s = 0.0

    @property
    def reason(self) -> str:
        return CLOCK_UNSTABLE_REASON if self.unstable else ""

    def check(self) -> bool:
        """Compare deltas; returns True when the clock is stable.

        Called every ``check_interval_s`` by the dispatcher loop. An unstable
        reading requires the full recovery streak (3 consecutive checks within
        the recovery tolerance) before leases may be acquired again.
        """

        now_mono = self._monotonic()
        now_wall = self._wall()
        mono_delta = now_mono - self._last_monotonic
        wall_delta = now_wall - self._last_wall
        self._last_monotonic = now_mono
        self._last_wall = now_wall
        self.last_delta_s = abs(mono_delta - wall_delta)
        if self.unstable:
            if self.last_delta_s <= self._recovery_tolerance_s:
                self._stable_streak += 1
                if self._stable_streak >= self._recovery_streak:
                    self.unstable = False
                    self._stable_streak = 0
            else:
                self._stable_streak = 0
        elif self.last_delta_s > self._unstable_tolerance_s:
            self.unstable = True
            self._stable_streak = 0
        return not self.unstable

    def due(self, last_check_monotonic: float) -> bool:
        """Whether another stability check is due (10s cadence)."""

        return self._monotonic() - last_check_monotonic >= self._check_interval_s
