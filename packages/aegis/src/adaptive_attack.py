"""50X Adaptive Attack Engine (task plan 19).

50X is controlled diversification across dimensions - NOT the same payload sent
50 times. Bounded by the safety budget and stopped by the kill switch. Deterministic
given a seed; variants are de-duplicated; non-destructive by default.
"""
from __future__ import annotations

import random
from typing import Optional

from planner import AttackCandidate

DIMENSIONS = ("syntax", "encoding", "context", "role", "state", "capability",
              "route", "chain", "architecture", "model")
_ENCODINGS = ("plain", "base64", "homoglyph", "leetspeak", "unicode_escape")
_ROLES = ("user", "system", "tool", "developer")
_CONTEXTS = ("baseline", "roleplay", "nested", "multiturn")


class AdaptiveAttackEngine:
    def expand(self, seed_candidate: AttackCandidate, *, factor: int, safety_budget,
               kill_switch=None, tenant_id: Optional[str] = None,
               seed: int = 0) -> list[AttackCandidate]:
        rng = random.Random(seed)
        campaign_id = safety_budget.roe.campaign_id
        variants: list[AttackCandidate] = []
        seen: set[tuple] = set()
        attempts = 0
        max_attempts = factor * 5  # bounded search, no unbounded branching
        while len(variants) < factor and attempts < max_attempts:
            attempts += 1
            if kill_switch is not None and kill_switch.is_tripped(
                    campaign_id=campaign_id, tenant_id=tenant_id):
                break
            if safety_budget.exhausted():
                break
            combo = (rng.choice(_ENCODINGS), rng.choice(_ROLES), rng.choice(_CONTEXTS),
                     rng.randint(1, 3))  # chain depth
            if combo in seen:
                continue
            seen.add(combo)
            safety_budget.consume_mutation()
            enc, role, ctx, depth = combo
            variants.append(AttackCandidate(
                candidate_id=f"{seed_candidate.candidate_id}-v{len(variants)}",
                technique=seed_candidate.technique,
                dimensions={"encoding": enc, "role": role, "context": ctx, "chain_depth": depth},
                payload=f"[{seed_candidate.technique}|{enc}|{role}|{ctx}|d{depth}]",
                capability=seed_candidate.capability,
                destructive=False,
                precondition=seed_candidate.precondition,
                expected_evidence=seed_candidate.expected_evidence))
        return variants
