"""Rules of Engagement + Safety Budget for red-team campaigns (task plan 25).

No campaign runs without RoE. Every long/privileged operation respects a bounded
budget. Default is NON-DESTRUCTIVE; destructive actions require explicit RoE.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from enums import RedTeamReason


@dataclass(frozen=True)
class RulesOfEngagement:
    campaign_id: str
    authorized_targets: frozenset[str]
    environment: str
    kill_switch_owner: str
    ip_cidrs: tuple[str, ...] = field(default_factory=tuple)
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    max_concurrency: int = 4
    request_budget: int = 1000
    mutation_budget: int = 5000
    destructive_permitted: bool = False  # non-destructive by default

    def target_authorized(self, target: str) -> bool:
        return target in self.authorized_targets

    def window_open(self, now: float) -> bool:
        if self.window_start is not None and now < self.window_start:
            return False
        if self.window_end is not None and now > self.window_end:
            return False
        return True


class BudgetExceeded(RuntimeError):
    def __init__(self, reason: RedTeamReason):
        super().__init__(reason.value)
        self.reason = reason


class SafetyBudget:
    def __init__(self, roe: RulesOfEngagement, *, clock=None) -> None:
        self._roe = roe
        self._clock = clock or time.monotonic
        self.requests = 0
        self.mutations = 0
        self.concurrency = 0
        self.destructive = 0

    @property
    def roe(self) -> RulesOfEngagement:
        return self._roe

    def check_target(self, target: str) -> None:
        if not self._roe.target_authorized(target):
            raise BudgetExceeded(RedTeamReason.ROE_TARGET_UNAUTHORIZED)
        if not self._roe.window_open(self._clock()):
            raise BudgetExceeded(RedTeamReason.ROE_WINDOW_CLOSED)

    def consume_request(self) -> None:
        if self.requests >= self._roe.request_budget:
            raise BudgetExceeded(RedTeamReason.SAFETY_BUDGET_EXHAUSTED)
        self.requests += 1

    def consume_mutation(self, n: int = 1) -> None:
        if self.mutations + n > self._roe.mutation_budget:
            raise BudgetExceeded(RedTeamReason.SAFETY_BUDGET_EXHAUSTED)
        self.mutations += n

    def enter(self) -> None:
        if self.concurrency >= self._roe.max_concurrency:
            raise BudgetExceeded(RedTeamReason.SAFETY_BUDGET_EXHAUSTED)
        self.concurrency += 1

    def leave(self) -> None:
        self.concurrency = max(0, self.concurrency - 1)

    def authorize_destructive(self) -> None:
        if not self._roe.destructive_permitted:
            raise BudgetExceeded(RedTeamReason.DESTRUCTIVE_ACTION_BLOCKED)
        self.destructive += 1

    def exhausted(self) -> bool:
        return (self.requests >= self._roe.request_budget
                or self.mutations >= self._roe.mutation_budget)
