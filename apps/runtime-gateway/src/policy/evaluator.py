"""Runtime policy evaluator: active (cached) ruleset + pure package evaluator.

Thin wrapper composing the provider with the deterministic package-level
`evaluate`. Kept separate so callers can evaluate against the active policy
without re-implementing cache lookup.
"""
from __future__ import annotations

from typing import Optional

from capability_registry import CapabilityResolution  # packages/policy/src
from decisions import PolicyDecision  # packages/domain/src
from enums import CacheSource, Environment  # packages/domain/src
from evaluator import evaluate  # packages/policy/src (pure)

from policy.artifact_loader import ActivePolicyProvider


class RuntimePolicyEvaluator:
    def __init__(self, provider: ActivePolicyProvider) -> None:
        self._provider = provider

    def active(self) -> tuple:
        ruleset, src, _ = self._provider.get_active()
        return ruleset, src

    def evaluate_request(
        self, *, environment: Environment, resolution: CapabilityResolution,
        resource_scope: Optional[str], dependency_ok: bool = True,
    ) -> tuple[PolicyDecision, CacheSource]:
        ruleset, src, _ = self._provider.get_active()
        decision = evaluate(
            ruleset, environment=environment, resolution=resolution,
            resource_scope=resource_scope, dependency_ok=dependency_ok,
        )
        return decision, src
