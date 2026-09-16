"""Deterministic evaluation of a compiled policy -> PolicyDecision.

Pure function of (optimized ruleset, environment, capability resolution, resource
scope, dependency health) plus optional runtime signals (deterministic detectors,
trajectory chain risk, precomputed AEGIS risk). Signals may only ESCALATE an
ALLOW to a more restrictive outcome - they never relax a BLOCK/approval decision.
No I/O, no LLM, bounded - safe for the hot path.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from capability_registry import CapabilityResolution, ToolCapability
from decisions import PolicyDecision
from enums import (
    ApprovalMode, Decision, DetectorSeverity, Environment, FailMode, ReasonCode, Sensitivity,
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
    return FailMode.FAIL_CLOSED


def _risk(ruleset: OptimizedRuleset, record: Optional[ToolCapability]) -> float:
    if record is None:
        return round(ruleset.unknown_weight, 4)
    score = (
        ruleset.sensitivity_weights.get(record.sensitivity.value, 0.0)
        + ruleset.side_effect_weights.get(record.side_effect.value, 0.0)
    )
    return round(min(score, 1.0), 4)


def _escalate(
    base: PolicyDecision, *,
    detector_severity: Optional[DetectorSeverity],
    detector_reasons: tuple[ReasonCode, ...],
    chain_egress: bool,
    precomputed_high: bool,
) -> PolicyDecision:
    """Only ALLOW is escalated; more restrictive never relaxed."""
    if base.decision != Decision.ALLOW:
        return base
    if detector_severity == DetectorSeverity.CRITICAL:
        return replace(base, decision=Decision.BLOCK,
                       reason_codes=(ReasonCode.DETECTOR_ESCALATION_CRITICAL,) + detector_reasons
                       + (ReasonCode.BUILTIN_RULESET,), risk_score=max(base.risk_score, 0.9))
    if detector_severity == DetectorSeverity.HIGH or chain_egress:
        reasons: list[ReasonCode] = []
        if detector_severity == DetectorSeverity.HIGH:
            reasons.append(ReasonCode.DETECTOR_ESCALATION_HIGH)
        if chain_egress:
            reasons.append(ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS)
        return replace(base, decision=Decision.SANDBOX,
                       reason_codes=tuple(reasons) + detector_reasons + (ReasonCode.BUILTIN_RULESET,),
                       risk_score=max(base.risk_score, 0.7))
    if precomputed_high:
        return replace(base, decision=Decision.REQUIRE_APPROVAL,
                       reason_codes=(ReasonCode.PRECOMPUTED_RISK_HIGH, ReasonCode.BUILTIN_RULESET),
                       risk_score=max(base.risk_score, 0.7))
    return base


def evaluate(
    ruleset: OptimizedRuleset,
    *,
    environment: Environment,
    resolution: CapabilityResolution,
    resource_scope: Optional[str],
    dependency_ok: bool = True,
    detector_severity: Optional[DetectorSeverity] = None,
    detector_reasons: tuple[ReasonCode, ...] = (),
    chain_egress: bool = False,
    precomputed_high: bool = False,
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

    base = build(Decision.ALLOW, [ReasonCode.ALLOWED_LOW_RISK, ReasonCode.CAPABILITY_KNOWN])
    return _escalate(base, detector_severity=detector_severity, detector_reasons=detector_reasons,
                     chain_egress=chain_egress, precomputed_high=precomputed_high)
