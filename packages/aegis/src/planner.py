"""Attack Planner (task plan 19).

Plans only against authorized targets under RoE and a safety budget. Every step
declares a precondition and expected evidence, defaults to non-destructive, and
the plan is bounded (no unbounded recursion/branching). Deterministic given a seed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

TECHNIQUES = (
    "prompt_injection", "tool_injection", "capability_spoofing", "resource_scope_escape",
    "approval_replay", "cache_poisoning", "trajectory_evasion", "ssrf", "data_exfiltration",
)


@dataclass(frozen=True)
class AttackCandidate:
    candidate_id: str
    technique: str
    dimensions: dict
    payload: str
    capability: Optional[str] = None
    destructive: bool = False
    precondition: str = ""
    expected_evidence: str = ""


@dataclass(frozen=True)
class AttackPlan:
    campaign_id: str
    target: str
    steps: tuple[AttackCandidate, ...] = field(default_factory=tuple)


class AttackPlanner:
    def plan(self, *, target: str, safety_budget, seed: int = 0,
             max_steps: int = 8) -> AttackPlan:
        safety_budget.check_target(target)  # RoE: authorized target + window
        rng = random.Random(seed)
        n = min(max_steps, len(TECHNIQUES))
        techniques = rng.sample(TECHNIQUES, n)
        steps = []
        for i, tech in enumerate(techniques):
            steps.append(AttackCandidate(
                candidate_id=f"{safety_budget.roe.campaign_id}-s{i}",
                technique=tech,
                dimensions={"context": "baseline"},
                payload=f"[{tech}] baseline probe",
                destructive=False,  # non-destructive default
                precondition=f"target reachable; capability path for {tech}",
                expected_evidence="deterministic policy/trace or sandbox observation"))
        return AttackPlan(campaign_id=safety_budget.roe.campaign_id, target=target,
                          steps=tuple(steps))
