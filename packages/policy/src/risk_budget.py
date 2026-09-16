"""Per-tenant/identity risk budget (master arch 7 PDP input; task plan owner: Developer A).

Bounds cumulative runtime risk over a rolling window. When a subject exceeds its
budget the pipeline escalates an ALLOW to REQUIRE_APPROVAL. Bounded + tenant-safe.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskBudgetPolicy:
    window_s: float = 60.0
    max_cumulative_risk: float = 5.0
    max_high_risk_events: int = 10
    high_risk_threshold: float = 0.7


class RiskBudgetStore:
    def __init__(self, policy: RiskBudgetPolicy = RiskBudgetPolicy(), *, clock=None) -> None:
        self._p = policy
        self._clock = clock or time.monotonic
        self._events: dict[tuple[str, str], deque] = {}

    def _key(self, tenant_id: str, identity_id: str) -> tuple[str, str]:
        return (tenant_id or "-", identity_id or "-")

    def _prune(self, dq: deque, now: float) -> None:
        while dq and now - dq[0][0] > self._p.window_s:
            dq.popleft()

    def record_and_check(self, *, tenant_id: str, identity_id: str, risk: float) -> bool:
        """Record a risk contribution; return True if the subject is now over budget."""
        now = self._clock()
        dq = self._events.setdefault(self._key(tenant_id, identity_id), deque())
        self._prune(dq, now)
        dq.append((now, float(risk)))
        cumulative = sum(r for _, r in dq)
        high = sum(1 for _, r in dq if r >= self._p.high_risk_threshold)
        return cumulative > self._p.max_cumulative_risk or high > self._p.max_high_risk_events
