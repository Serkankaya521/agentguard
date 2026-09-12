"""Policy Enforcement Point (PEP): enforces a decision. It never produces one.

Keeping PEP and PDP separate is a non-negotiable boundary (AGENTS.md #3). The
PEP maps a PolicyDecision onto an enforcement outcome and the resulting action
state, preserving the blocked/proposed/approved/executed distinction. The actual
Execution Gate (signature/replay/TOCTOU checks) lands in Sprint A3; here the PEP
classifies whether execution may proceed.
"""
from __future__ import annotations

from dataclasses import dataclass

from decisions import PolicyDecision
from enums import ActionState, Decision

# Only ALLOW permits the tool to run in A1. Everything else withholds execution.
_PERMITS_EXECUTION = {Decision.ALLOW}


@dataclass(frozen=True)
class EnforcementOutcome:
    permit_execution: bool
    action_state: ActionState
    decision: PolicyDecision


class PolicyEnforcementPoint:
    def enforce(self, decision: PolicyDecision) -> EnforcementOutcome:
        if decision.decision in _PERMITS_EXECUTION:
            # Permitted at the policy layer; the Execution Gate performs the run
            # and transitions PROPOSED -> EXECUTED. Until then it stays PROPOSED.
            return EnforcementOutcome(True, ActionState.PROPOSED, decision)
        if decision.decision == Decision.BLOCK:
            return EnforcementOutcome(False, ActionState.BLOCKED, decision)
        # REQUIRE_APPROVAL / SANDBOX / STEP_UP_AUTH / REDACT / ASYNC_DEEP_ANALYSIS
        # withhold execution and remain a proposal pending the slow-path outcome.
        return EnforcementOutcome(False, ActionState.PROPOSED, decision)
