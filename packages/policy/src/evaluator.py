"""Deterministic evaluation of a compiled policy -> PolicyDecision.

Pure function of (optimized ruleset, environment, capability resolution, resource
scope, dependency health). No I/O, no LLM, bounded work - safe for the hot path.
Reproduces the Sprint A1 decision semantics, now driven by the compiled artifact.
"""
from __future__ import annotations

from typing import Optional

from capability_registry import CapabilityResolution, ToolCapability
from decisions import PolicyDecision
from enums import (
    ApprovalMode, Decision, Environment, FailMode, ReasonCode, Sensitivity,
)
from optimizer import OptimizedRuleset


def fail_mode_for(ruleset: OptimizedRuleset, capability_id: Optional[str],
                  record: Optional[ToolCapability]) -> FailMode:
    if capability_id in ruleset.fail_closed:
        return FailMode.FAIL_CLOSED
    if record is not None and record.sensitivity == Sensitivity.LOW and (
        record.fail_open_allowed or capability_id in ruleset.fail_open
    ):
        return FailMode.FAIL_OPEN
    return FailMode.FAIL_CLOSED  # safe default


def _risk(ruleset: OptimizedRuleset, record: Optional[ToolCapability]) -> float:
    if record is None:
        return round(ruleset.unknown_weight, 4)
    score = (
        ruleset.sensitivity_weights.get(record.sensitivity.value, 0.0)
        + ruleset.side_effect_weights.get(record.side_effect.value, 0.0)
    )
    return round(min(score, 1.0), 4)


def evaluate(
    ruleset: OptimizedRuleset,
    *,
    environment: Environment,
    resolution: CapabilityResolution,
    resource_scope: Optional[str],
    dependency_ok: bool = True,
) -> PolicyDecision:
    record = resolution.record
    capability_id = resolution.capability_id
    fail_mode = fail_mode_for(ruleset, capability_id, record)
    risk = _risk(ruleset, record)

    def build(decision: Decision, reasons: list[ReasonCode]) -> PolicyDecision:
        return PolicyDecision(
            decision=decision,
            reason_codes=tuple(reasons) + (ReasonCode.BUILTIN_RULESET,),
            risk_score=risk,
            fail_mode=fail_mode,
            policy_version=ruleset.policy_version,
            policy_hash=ruleset.policy_hash,
            capability_id=capability_id,
        )

    if not dependency_ok:
        if fail_mode == FailMode.FAIL_CLOSED:
            return build(Decision.BLOCK, [ReasonCode.FAIL_CLOSED_DEPENDENCY])
        return build(Decision.ALLOW, [ReasonCode.FAIL_OPEN_POLICY])

    if resolution.mismatch:
        return build(Decision.BLOCK, [ReasonCode.CAPABILITY_MISMATCH])

    if not resolution.known:
        if environment == Environment.PRODUCTION:
            return build(ruleset.unknown_production, [ReasonCode.BLOCKED_UNKNOWN_CAPABILITY_PROD])
        return build(ruleset.unknown_default, [ReasonCode.APPROVAL_REQUIRED_UNKNOWN_CAPABILITY])

    assert record is not None
    if not record.resource_in_scope(resource_scope):
        return build(Decision.BLOCK, [ReasonCode.RESOURCE_SCOPE_VIOLATION])

    if record.approval_mode == ApprovalMode.ALWAYS:
        return build(Decision.REQUIRE_APPROVAL, [ReasonCode.APPROVAL_REQUIRED_ALWAYS])
    if record.approval_mode == ApprovalMode.CONDITIONAL and record.sensitivity in (
        Sensitivity.HIGH, Sensitivity.CRITICAL
    ):
        return build(Decision.REQUIRE_APPROVAL, [ReasonCode.APPROVAL_REQUIRED_CONDITIONAL])

    if environment == Environment.PRODUCTION and (
        (record.sensitivity == Sensitivity.CRITICAL and ruleset.critical_requires_approval)
        or record.side_effect in ruleset.destructive
    ):
        reason = (
            ReasonCode.BLOCKED_HIGH_SENSITIVITY
            if record.sensitivity == Sensitivity.CRITICAL
            else ReasonCode.BLOCKED_DESTRUCTIVE_SIDE_EFFECT
        )
        return build(Decision.REQUIRE_APPROVAL, [reason, ReasonCode.CAPABILITY_KNOWN])

    return build(Decision.ALLOW, [ReasonCode.ALLOWED_LOW_RISK, ReasonCode.CAPABILITY_KNOWN])
