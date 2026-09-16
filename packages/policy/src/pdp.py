"""Policy Decision Point (PDP): produces a PolicyDecision. It never enforces.

The PDP now consumes a *compiled* policy artifact (Sprint A2) instead of a
hardcoded ruleset. The default compiled policy reproduces the A1 semantics, so
the decide() contract is unchanged.
"""
from __future__ import annotations

from typing import Optional

from artifacts import CompiledPolicy
from capability_registry import CapabilityResolution
from compiler import default_compiled_policy
from decisions import PolicyDecision
from enums import Environment
from evaluator import evaluate
from optimizer import OptimizedRuleset, optimize

# Backwards-compatible identifiers for the built-in policy.
BUILTIN_POLICY_VERSION = default_compiled_policy().policy_version
BUILTIN_POLICY_HASH = default_compiled_policy().policy_hash

# High-impact capabilities that must fail closed (exposed for reference/tests).
FAIL_CLOSED_CAPABILITIES = frozenset(
    default_compiled_policy().ruleset.get("fail_closed_capabilities", ())
)


class PolicyDecisionPoint:
    def __init__(self, compiled: Optional[CompiledPolicy] = None) -> None:
        self._compiled = compiled or default_compiled_policy()
        self._ruleset: OptimizedRuleset = optimize(self._compiled)

    @property
    def policy_version(self) -> str:
        return self._ruleset.policy_version

    @property
    def policy_hash(self) -> str:
        return self._ruleset.policy_hash

    def decide(
        self,
        *,
        environment: Environment,
        resolution: CapabilityResolution,
        resource_scope: Optional[str],
        dependency_ok: bool = True,
    ) -> PolicyDecision:
        return evaluate(
            self._ruleset,
            environment=environment,
            resolution=resolution,
            resource_scope=resource_scope,
            dependency_ok=dependency_ok,
        )
