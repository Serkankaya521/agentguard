"""Policy Decision Point (PDP): produces a PolicyDecision. It never enforces.

Sprint A1 uses a deterministic built-in ruleset (no compiled policy artifact yet
- that arrives in A2). The decision is explainable via stable reason codes and
reproducible for identical inputs.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from capability_registry import CapabilityResolution, ToolCapability
from decisions import PolicyDecision
from enums import (
    ApprovalMode, Decision, Environment, FailMode, ReasonCode, Sensitivity, SideEffect,
)

BUILTIN_POLICY_VERSION = "builtin/1.0.0"
BUILTIN_POLICY_HASH = "sha256:" + hashlib.sha256(BUILTIN_POLICY_VERSION.encode()).hexdigest()

# High-impact capability families that must fail closed (master arch 30.13).
FAIL_CLOSED_CAPABILITIES: frozenset[str] = frozenset({
    "payment.execute", "secret.read", "identity.admin", "shell.execute",
    "code.execute", "database.delete", "database.write", "network.admin",
    "network.egress", "agent.delegate",
})

_SENSITIVITY_BASE = {
    Sensitivity.LOW: 0.10, Sensitivity.MEDIUM: 0.35,
    Sensitivity.HIGH: 0.65, Sensitivity.CRITICAL: 0.90,
}
_SIDE_EFFECT_WEIGHT = {
    SideEffect.NONE: 0.0, SideEffect.READ: 0.05, SideEffect.WRITE: 0.20,
    SideEffect.DELETE: 0.40, SideEffect.NETWORK: 0.30, SideEffect.EXECUTE: 0.40,
    SideEffect.ADMIN: 0.50,
}
_DESTRUCTIVE = {SideEffect.DELETE, SideEffect.EXECUTE, SideEffect.ADMIN}


def _fail_mode_for(capability_id: Optional[str], record: Optional[ToolCapability]) -> FailMode:
    if capability_id in FAIL_CLOSED_CAPABILITIES:
        return FailMode.FAIL_CLOSED
    if record is not None and record.sensitivity == Sensitivity.LOW and record.fail_open_allowed:
        return FailMode.FAIL_OPEN
    return FailMode.FAIL_CLOSED  # safe default


def _risk_score(record: Optional[ToolCapability]) -> float:
    if record is None:
        return 0.75  # unknown is treated as elevated risk
    score = _SENSITIVITY_BASE[record.sensitivity] + _SIDE_EFFECT_WEIGHT[record.side_effect]
    return round(min(score, 1.0), 4)


class PolicyDecisionPoint:
    def decide(
        self,
        *,
        environment: Environment,
        resolution: CapabilityResolution,
        resource_scope: Optional[str],
        dependency_ok: bool = True,
    ) -> PolicyDecision:
        record = resolution.record
        capability_id = resolution.capability_id
        fail_mode = _fail_mode_for(capability_id, record)
        risk = _risk_score(record)

        def build(decision: Decision, reasons: list[ReasonCode]) -> PolicyDecision:
            return PolicyDecision(
                decision=decision,
                reason_codes=tuple(reasons) + (ReasonCode.BUILTIN_RULESET,),
                risk_score=risk,
                fail_mode=fail_mode,
                policy_version=BUILTIN_POLICY_VERSION,
                policy_hash=BUILTIN_POLICY_HASH,
                capability_id=capability_id,
            )

        # 1) Hot-path dependency failure -> apply capability fail mode.
        if not dependency_ok:
            if fail_mode == FailMode.FAIL_CLOSED:
                return build(Decision.BLOCK, [ReasonCode.FAIL_CLOSED_DEPENDENCY])
            return build(Decision.ALLOW, [ReasonCode.FAIL_OPEN_POLICY])

        # 2) Capability spoofing: declared capability not authoritative for tool.
        if resolution.mismatch:
            return build(Decision.BLOCK, [ReasonCode.CAPABILITY_MISMATCH])

        # 3) Unknown capability is never silently trusted.
        if not resolution.known:
            if environment == Environment.PRODUCTION:
                return build(Decision.BLOCK, [ReasonCode.BLOCKED_UNKNOWN_CAPABILITY_PROD])
            return build(Decision.REQUIRE_APPROVAL, [ReasonCode.APPROVAL_REQUIRED_UNKNOWN_CAPABILITY])

        assert record is not None
        # 4) Resource scope enforcement.
        if not record.resource_in_scope(resource_scope):
            return build(Decision.BLOCK, [ReasonCode.RESOURCE_SCOPE_VIOLATION])

        # 5) Approval mode.
        if record.approval_mode == ApprovalMode.ALWAYS:
            return build(Decision.REQUIRE_APPROVAL, [ReasonCode.APPROVAL_REQUIRED_ALWAYS])
        if record.approval_mode == ApprovalMode.CONDITIONAL and record.sensitivity in (
            Sensitivity.HIGH, Sensitivity.CRITICAL
        ):
            return build(Decision.REQUIRE_APPROVAL, [ReasonCode.APPROVAL_REQUIRED_CONDITIONAL])

        # 6) Critical sensitivity or destructive side effect in production needs approval.
        if environment == Environment.PRODUCTION and (
            record.sensitivity == Sensitivity.CRITICAL or record.side_effect in _DESTRUCTIVE
        ):
            reason = (
                ReasonCode.BLOCKED_HIGH_SENSITIVITY
                if record.sensitivity == Sensitivity.CRITICAL
                else ReasonCode.BLOCKED_DESTRUCTIVE_SIDE_EFFECT
            )
            return build(Decision.REQUIRE_APPROVAL, [reason, ReasonCode.CAPABILITY_KNOWN])

        # 7) Otherwise allow.
        return build(Decision.ALLOW, [ReasonCode.ALLOWED_LOW_RISK, ReasonCode.CAPABILITY_KNOWN])
