"""Sandbox execution requirements (task plan 45).

Enforces the requirements for isolated red-team execution: non-destructive by
default, no network unless RoE allows, bounded operations, capability scope.
Real OS/container isolation is platform (Developer B) infrastructure; this
enforces the policy and provides a safe, reproducible simulated executor that
never performs a real destructive or networked action.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass(frozen=True)
class SandboxPolicy:
    non_destructive: bool = True
    network_allowed: bool = False
    allowed_capabilities: frozenset[str] = field(default_factory=frozenset)
    max_ops: int = 100


@dataclass(frozen=True)
class SandboxResult:
    ran: bool
    observations: tuple[dict, ...]
    refused_reason: Optional[str] = None


class SandboxViolation(RuntimeError):
    pass


class SandboxExecutor:
    """Deterministic, safe executor. Refuses anything the policy forbids."""

    def execute(self, candidate: dict, policy: SandboxPolicy,
                observe: Optional[Callable[[dict], dict]] = None) -> SandboxResult:
        if candidate.get("destructive") and policy.non_destructive:
            return SandboxResult(False, (), "destructive_action_refused")
        if candidate.get("network") and not policy.network_allowed:
            return SandboxResult(False, (), "network_refused")
        cap = candidate.get("capability")
        if policy.allowed_capabilities and cap not in policy.allowed_capabilities:
            return SandboxResult(False, (), "capability_out_of_scope")
        ops = min(int(candidate.get("ops", 1)), policy.max_ops)
        # Safe simulated observation; never performs real side effects.
        obs = observe(candidate) if observe else {"simulated": True, "ops": ops}
        return SandboxResult(True, (obs,), None)
