"""Cooperative latency budget for the hot path.

Python cannot preempt CPU-bound code, so budgets here are cooperative deadlines
plus measurement: operations check `Deadline.exceeded()`, and the pipeline
records latency and flags overruns. I/O dependency timeouts are enforced by the
clients (e.g. Redis socket_timeout). SLO: p50<2ms, p99<10ms, max<20ms.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

GLOBAL_BUDGET_US = 20_000  # critical maximum under normal load


@dataclass
class Deadline:
    budget_us: int
    _start_ns: int = 0

    def __post_init__(self) -> None:
        self._start_ns = time.perf_counter_ns()

    def elapsed_us(self) -> int:
        return (time.perf_counter_ns() - self._start_ns) // 1000

    def remaining_us(self) -> int:
        return self.budget_us - self.elapsed_us()

    def exceeded(self) -> bool:
        return self.elapsed_us() > self.budget_us


def start(budget_us: int = GLOBAL_BUDGET_US) -> Deadline:
    return Deadline(budget_us=budget_us)
