"""Runtime-optimized view of a compiled ruleset (O(1) hot-path lookups)."""
from __future__ import annotations

from dataclasses import dataclass

from artifacts import CompiledPolicy
from enums import Decision, SideEffect


@dataclass(frozen=True)
class OptimizedRuleset:
    policy_id: str
    policy_version: str
    policy_hash: str
    fail_closed: frozenset[str]
    fail_open: frozenset[str]
    unknown_production: Decision
    unknown_default: Decision
    destructive: frozenset[SideEffect]
    critical_requires_approval: bool
    sensitivity_weights: dict
    side_effect_weights: dict
    unknown_weight: float


def optimize(compiled: CompiledPolicy) -> OptimizedRuleset:
    r = compiled.ruleset
    return OptimizedRuleset(
        policy_id=compiled.policy_id,
        policy_version=compiled.policy_version,
        policy_hash=compiled.policy_hash,
        fail_closed=frozenset(r.get("fail_closed_capabilities", ())),
        fail_open=frozenset(r.get("fail_open_capabilities", ())),
        unknown_production=Decision(r["unknown_capability"]["production"]),
        unknown_default=Decision(r["unknown_capability"]["default"]),
        destructive=frozenset(SideEffect(s) for s in r.get("destructive_side_effects", ())),
        critical_requires_approval=bool(r.get("critical_requires_approval", True)),
        sensitivity_weights=dict(r["risk_weights"]["sensitivity"]),
        side_effect_weights=dict(r["risk_weights"]["side_effect"]),
        unknown_weight=float(r["risk_weights"]["unknown"]),
    )
