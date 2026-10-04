"""Injectable time source.

All expiry decisions in the kernel read time through a :class:`Clock` so tests
can move time deterministically instead of sleeping. Time is whole seconds
since the Unix epoch; sub-second precision adds nothing to approval windows
measured in minutes and makes stored values harder to compare.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    def now(self) -> int:
        """Return the current time as integer epoch seconds."""
        ...


class SystemClock:
    """Wall-clock time."""

    def now(self) -> int:
        return int(time.time())


class ManualClock:
    """A clock that only moves when told to. Safe to read from many threads."""

    def __init__(self, start: int = 1_700_000_000) -> None:
        self._now = int(start)
        self._lock = threading.Lock()

    def now(self) -> int:
        with self._lock:
            return self._now

    def advance(self, seconds: int) -> int:
        if seconds < 0:
            raise ValueError("ManualClock cannot move backwards via advance()")
        with self._lock:
            self._now += int(seconds)
            return self._now

    def set(self, value: int) -> None:
        with self._lock:
            self._now = int(value)
