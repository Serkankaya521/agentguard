"""Per-dependency circuit breaker with bounded half-open trials.

Hot-path dependencies use strict timeouts and a breaker so a slow/failing
dependency cannot lock customer traffic (master arch 30.13). Half-open admits a
bounded number of trials to avoid a thundering herd on recovery.
"""
from __future__ import annotations

import threading
from typing import Callable, Optional


class CircuitOpen(RuntimeError):
    pass


class CircuitBreaker:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, *, failure_threshold: int = 5, reset_timeout_s: float = 5.0,
                 half_open_max: int = 1, clock: Optional[Callable[[], float]] = None) -> None:
        import time
        self._threshold = failure_threshold
        self._reset = reset_timeout_s
        self._half_open_max = half_open_max
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._state = self.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._half_open_inflight = 0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def _allow(self) -> bool:
        now = self._clock()
        if self._state == self.CLOSED:
            return True
        if self._state == self.OPEN:
            if now - self._opened_at >= self._reset:
                self._state = self.HALF_OPEN
                self._half_open_inflight = 0
            else:
                return False
        if self._state == self.HALF_OPEN:
            if self._half_open_inflight < self._half_open_max:
                self._half_open_inflight += 1
                return True
            return False
        return False

    def _on_success(self) -> None:
        self._state = self.CLOSED
        self._failures = 0
        self._half_open_inflight = 0

    def _on_failure(self) -> None:
        if self._state == self.HALF_OPEN:
            self._state = self.OPEN
            self._opened_at = self._clock()
            return
        self._failures += 1
        if self._failures >= self._threshold:
            self._state = self.OPEN
            self._opened_at = self._clock()

    def call(self, fn: Callable):
        with self._lock:
            if not self._allow():
                raise CircuitOpen("circuit open")
        try:
            result = fn()
        except Exception:
            with self._lock:
                self._on_failure()
            raise
        with self._lock:
            self._on_success()
        return result
