"""Red-team campaign orchestrator (security-owned worker job).

Ties the planner, 50X adaptive engine, safety budget, kill switch, and sandbox
together. Runs only under RoE, checks the kill switch at every step, defaults to
non-destructive, and stays within the safety budget. Produces observations and
candidates only - never a privilege or deployment change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from planner import AttackPlanner  # packages/aegis/src
from adaptive_attack import AdaptiveAttackEngine  # packages/aegis/src

from execution.safety_budget import BudgetExceeded, SafetyBudget  # apps/worker/src
from execution.sandbox import SandboxExecutor, SandboxPolicy


@dataclass(frozen=True)
class CampaignResult:
    campaign_id: str
    target: str
    executed: int = 0
    refused: int = 0
    killed: bool = False
    budget_exhausted: bool = False
    unauthorized: bool = False
    observations: tuple = field(default_factory=tuple)


class RedTeamCampaign:
    def __init__(self, *, planner=None, engine=None, sandbox=None) -> None:
        self._planner = planner or AttackPlanner()
        self._engine = engine or AdaptiveAttackEngine()
        self._sandbox = sandbox or SandboxExecutor()

    def run(self, *, target: str, safety_budget: SafetyBudget, kill_switch,
            tenant_id: Optional[str] = None, seed: int = 0, factor: int = 5,
            policy: Optional[SandboxPolicy] = None) -> CampaignResult:
        cid = safety_budget.roe.campaign_id
        policy = policy or SandboxPolicy()
        executed = refused = 0
        killed = exhausted = False
        observations: list = []

        try:
            plan = self._planner.plan(target=target, safety_budget=safety_budget, seed=seed)
        except BudgetExceeded:
            return CampaignResult(cid, target, unauthorized=True)

        for step in plan.steps:
            if kill_switch.is_tripped(campaign_id=cid, tenant_id=tenant_id):
                killed = True
                break
            try:
                safety_budget.enter()
            except BudgetExceeded:
                exhausted = True
                break
            try:
                variants = self._engine.expand(
                    step, factor=factor, safety_budget=safety_budget,
                    kill_switch=kill_switch, tenant_id=tenant_id, seed=seed)
                for cand in [step, *variants]:
                    if kill_switch.is_tripped(campaign_id=cid, tenant_id=tenant_id):
                        killed = True
                        break
                    try:
                        safety_budget.consume_request()
                    except BudgetExceeded:
                        exhausted = True
                        break
                    res = self._sandbox.execute(
                        {"destructive": cand.destructive, "network": False,
                         "capability": cand.capability, "ops": 1}, policy)
                    if res.ran:
                        executed += 1
                        observations.append({"candidate_id": cand.candidate_id,
                                             "technique": cand.technique})
                    else:
                        refused += 1
            finally:
                safety_budget.leave()
            if killed or exhausted:
                break

        return CampaignResult(cid, target, executed=executed, refused=refused,
                              killed=killed, budget_exhausted=exhausted,
                              observations=tuple(observations))
