"""Runtime gateway pipeline (Sprint A1 skeleton).

Wires the mandated hot-path sequence:

    normalize -> validate context -> capability lookup -> PDP -> PEP
    -> assemble RuntimeDecision (with correlation + latency metadata)

Not yet on the path (later sprints, represented as explicit seams, not faked):
  - compiled policy artifact + L1/L2 cache (A2)
  - deterministic detectors, incremental trajectory, precomputed risk,
    execution gate, approval-token validation, async event publication (A3)
"""
from __future__ import annotations

import time
import uuid
from typing import Optional

from config import RUNTIME_VERSION
from context import validate_context
from normalization import normalize

from capability_registry import CapabilityRegistry  # packages/policy/src
from pdp import PolicyDecisionPoint
from pep import EnforcementOutcome, PolicyEnforcementPoint

from decisions import PolicyDecision, RuntimeDecision  # packages/domain/src
from enums import (
    ActionState, CacheSource, Decision, FailMode, ReasonCode,
)
from pdp import BUILTIN_POLICY_HASH, BUILTIN_POLICY_VERSION


class RuntimeGatewayPipeline:
    """Stateless orchestrator. Safe to instantiate per-process and share."""

    def __init__(self, registry: Optional[CapabilityRegistry] = None) -> None:
        self._registry = registry or CapabilityRegistry()
        self._pdp = PolicyDecisionPoint()
        self._pep = PolicyEnforcementPoint()

    def process(self, raw: object, source: object) -> RuntimeDecision:
        start = time.perf_counter_ns()

        result = normalize(raw, source)
        if not result.ok or result.event is None:
            return self._reject(
                start, tenant_id=self._safe_tenant_id(raw),
                reasons=result.errors or [ReasonCode.NORMALIZATION_SCHEMA_INVALID],
            )

        event = result.event

        # Context validation: never guess tenant/identity/environment.
        context_errors = validate_context(event.tenant)
        if context_errors:
            return self._finalize(
                start, event.tenant.tenant_id, event.event_id, event.trace_id,
                PolicyDecision(
                    decision=Decision.BLOCK,
                    reason_codes=tuple(context_errors),
                    risk_score=1.0,
                    fail_mode=FailMode.FAIL_CLOSED,
                    policy_version=BUILTIN_POLICY_VERSION,
                    policy_hash=BUILTIN_POLICY_HASH,
                    capability_id=None,
                ),
                action_state=ActionState.BLOCKED,
            )

        resolution = self._registry.resolve(event.tool_id, event.declared_capability_id)
        decision = self._pdp.decide(
            environment=event.tenant.environment,
            resolution=resolution,
            resource_scope=event.resource_scope,
        )
        outcome: EnforcementOutcome = self._pep.enforce(decision)

        return self._finalize(
            start, event.tenant.tenant_id, event.event_id, event.trace_id,
            decision, action_state=outcome.action_state,
        )

    # --- helpers -----------------------------------------------------------
    @staticmethod
    def _safe_tenant_id(raw: object) -> str:
        if isinstance(raw, dict):
            t = raw.get("tenant")
            if isinstance(t, dict) and t.get("tenant_id"):
                return str(t["tenant_id"])
        return "unknown"

    def _reject(self, start: int, tenant_id: str, reasons: list[ReasonCode]) -> RuntimeDecision:
        return self._finalize(
            start, tenant_id, event_id="unknown", trace_id="unknown",
            decision=PolicyDecision(
                decision=Decision.BLOCK,
                reason_codes=tuple(reasons),
                risk_score=1.0,
                fail_mode=FailMode.FAIL_CLOSED,
                policy_version=BUILTIN_POLICY_VERSION,
                policy_hash=BUILTIN_POLICY_HASH,
                capability_id=None,
            ),
            action_state=ActionState.BLOCKED,
        )

    def _finalize(
        self, start: int, tenant_id: str, event_id: str, trace_id: str,
        decision: PolicyDecision, action_state: ActionState,
    ) -> RuntimeDecision:
        latency_us = max(0, (time.perf_counter_ns() - start) // 1000)
        return RuntimeDecision(
            decision_id=str(uuid.uuid4()),
            tenant_id=tenant_id or "unknown",
            event_id=event_id,
            trace_id=trace_id,
            policy_version=decision.policy_version,
            policy_hash=decision.policy_hash,
            runtime_version=RUNTIME_VERSION,
            risk_score=decision.risk_score,
            reason_codes=decision.reason_codes,
            cache_source=CacheSource.COMPUTED,  # no cache on the A1 path yet
            latency_us=int(latency_us),
            trajectory_version=0,  # trajectory engine v2 arrives in A3
            decision=decision.decision,
            fail_mode=decision.fail_mode,
            action_state=action_state,
            capability_id=decision.capability_id,
        )
