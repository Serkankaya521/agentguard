"""Multi-turn / chain exploration (task plan 22, 23; master arch 10).

Builds bounded multi-step attack chains with state carry-over across turns.
Deterministic given a seed, non-destructive by default, budget-bounded, and
kill-switch aware. Runs on the intelligence plane, never the hot path.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from planner import AttackCandidate

# Plausible follow-on techniques for each technique (chain transitions).
_TRANSITIONS = {
    "prompt_injection": ("tool_injection", "capability_spoofing", "data_exfiltration"),
    "tool_injection": ("resource_scope_escape", "data_exfiltration"),
    "capability_spoofing": ("resource_scope_escape", "data_exfiltration"),
    "resource_scope_escape": ("data_exfiltration",),
    "cache_poisoning": ("trajectory_evasion", "resource_scope_escape"),
    "trajectory_evasion": ("data_exfiltration",),
    "approval_replay": ("data_exfiltration",),
    "ssrf": ("data_exfiltration",),
    "data_exfiltration": (),
}


@dataclass(frozen=True)
class AttackChain:
    chain_id: str
    steps: tuple[AttackCandidate, ...]
    techniques: tuple[str, ...]
    state_carry: dict = field(default_factory=dict)

    @property
    def depth(self) -> int:
        return len(self.steps)


class ChainExplorer:
    def explore(self, *, seeds: list[AttackCandidate], max_depth: int, max_chains: int,
                safety_budget, kill_switch=None, tenant_id: Optional[str] = None,
                seed: int = 0) -> list[AttackChain]:
        rng = random.Random(seed)
        campaign_id = safety_budget.roe.campaign_id
        chains: list[AttackChain] = []
        seen: set[tuple] = set()

        for s in seeds:
            if len(chains) >= max_chains:
                break
            steps = [s]
            techniques = [s.technique]
            state = {"capabilities": [s.capability] if s.capability else []}
            for depth in range(1, max_depth):
                if kill_switch is not None and kill_switch.is_tripped(
                        campaign_id=campaign_id, tenant_id=tenant_id):
                    break
                if safety_budget.exhausted():
                    break
                options = _TRANSITIONS.get(techniques[-1], ())
                if not options:
                    break
                nxt = rng.choice(options)
                safety_budget.consume_mutation()
                techniques.append(nxt)
                steps.append(AttackCandidate(
                    candidate_id=f"{s.candidate_id}-c{depth}", technique=nxt,
                    dimensions={"chain_step": depth, "prior": techniques[-2]},
                    payload=f"[chain:{'->'.join(techniques)}]",
                    destructive=False,
                    precondition=f"prior step '{techniques[-2]}' succeeded",
                    expected_evidence="observed state carried from prior step"))
            sig = tuple(techniques)
            if sig in seen:
                continue
            seen.add(sig)
            chains.append(AttackChain(
                chain_id=f"{campaign_id}-chain{len(chains)}", steps=tuple(steps),
                techniques=tuple(techniques), state_carry=state))
        return chains
