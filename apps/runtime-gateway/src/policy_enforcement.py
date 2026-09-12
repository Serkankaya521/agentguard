"""Runtime gateway pipeline (Sprint A2: ultra-fast policy path).

Sequence:
    (cached compiled policy) normalize -> validate context
    -> capability lookup (cache + circuit breaker) -> evaluate compiled policy
    -> PEP -> RuntimeDecision (with cache_source + latency metadata)

A2 adds: compiled policy artifact consumption, L1/L2 tiered cache, circuit
breaker with capability-based fail mode on dependency failure, latency budget
measurement. Still deferred (A3, explicit seams): deterministic detectors,
incremental trajectory v2, precomputed risk, execution gate, approval-token
validation, async event publication.
"""
from __future__ import annotations

import uuid
from typing import Optional

from config import RUNTIME_VERSION
from context import validate_context
from normalization import normalize

from cache import TieredCache, make_key  # apps/runtime-gateway/src/cache
from hot_path import latency_budget
from hot_path.circuit_breaker import CircuitBreaker
from policy.artifact_loader import ActivePolicyProvider

from capability_registry import CapabilityRegistry, CapabilityResolution  # packages/policy/src
from evaluator import evaluate  # packages/policy/src (pure)
from pep import EnforcementOutcome, PolicyEnforcementPoint  # packages/policy/src

from decisions import PolicyDecision, RuntimeDecision  # packages/domain/src
from enums import ActionState, CacheSource, Decision, FailMode, ReasonCode

_CACHE_RANK = {CacheSource.NONE: 0, CacheSource.L1: 1, CacheSource.L2: 2, CacheSource.COMPUTED: 3}


def _worst(a: CacheSource, b: CacheSource) -> CacheSource:
    return a if _CACHE_RANK[a] >= _CACHE_RANK[b] else b


class RuntimeGatewayPipeline:
    """Stateless orchestrator. Safe to share across requests/threads."""

    def __init__(
        self,
        registry: Optional[CapabilityRegistry] = None,
        *,
        cache: Optional[TieredCache] = None,
        provider: Optional[ActivePolicyProvider] = None,
        breaker: Optional[CircuitBreaker] = None,
        budget_us: int = latency_budget.GLOBAL_BUDGET_US,
    ) -> None:
        self._registry = registry or CapabilityRegistry()
        self._cache = cache or TieredCache()
        self._provider = provider or ActivePolicyProvider(cache=self._cache)
        self._pep = PolicyEnforcementPoint()
        self._breaker = breaker or CircuitBreaker()
        self._budget_us = budget_us

    def process(self, raw: object, source: object) -> RuntimeDecision:
        deadline = latency_budget.start(self._budget_us)
        ruleset, policy_src, _ = self._provider.get_active()

        result = normalize(raw, source)
        if not result.ok or result.event is None:
            return self._finalize(
                deadline, ruleset, self._safe_tenant_id(raw), "unknown", "unknown",
                self._block(ruleset, tuple(result.errors or (ReasonCode.NORMALIZATION_SCHEMA_INVALID,))),
                ActionState.BLOCKED, CacheSource.COMPUTED,
            )

        event = result.event

        context_errors = validate_context(event.tenant)
        if context_errors:
            return self._finalize(
                deadline, ruleset, event.tenant.tenant_id, event.event_id, event.trace_id,
                self._block(ruleset, tuple(context_errors)),
                ActionState.BLOCKED, policy_src,
            )

        # Capability lookup through cache + circuit breaker. A dependency failure
        # is not a security finding; it triggers the capability fail mode.
        cap_key = make_key("cap", "reg", event.tool_id, event.declared_capability_id or "-")
        try:
            resolution, cap_src = self._cache.get_or_compute(
                cap_key,
                lambda: self._breaker.call(
                    lambda: self._registry.resolve(event.tool_id, event.declared_capability_id)
                ),
            )
            dependency_ok = True
        except Exception:
            resolution = CapabilityResolution(
                known=False, record=None,
                capability_id=event.declared_capability_id, mismatch=False,
            )
            cap_src = CacheSource.COMPUTED
            dependency_ok = False

        decision = evaluate(
            ruleset, environment=event.tenant.environment, resolution=resolution,
            resource_scope=event.resource_scope, dependency_ok=dependency_ok,
        )
        outcome: EnforcementOutcome = self._pep.enforce(decision)

        return self._finalize(
            deadline, ruleset, event.tenant.tenant_id, event.event_id, event.trace_id,
            decision, outcome.action_state, _worst(policy_src, cap_src),
        )

    # --- helpers -----------------------------------------------------------
    @staticmethod
    def _safe_tenant_id(raw: object) -> str:
        if isinstance(raw, dict):
            t = raw.get("tenant")
            if isinstance(t, dict) and t.get("tenant_id"):
                return str(t["tenant_id"])
        return "unknown"

    @staticmethod
    def _block(ruleset, reasons: tuple) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.BLOCK, reason_codes=reasons, risk_score=1.0,
            fail_mode=FailMode.FAIL_CLOSED, policy_version=ruleset.policy_version,
            policy_hash=ruleset.policy_hash, capability_id=None,
        )

    def _finalize(
        self, deadline, ruleset, tenant_id: str, event_id: str, trace_id: str,
        decision: PolicyDecision, action_state: ActionState, cache_source: CacheSource,
    ) -> RuntimeDecision:
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
            cache_source=cache_source,
            latency_us=int(max(0, deadline.elapsed_us())),
            trajectory_version=0,  # incremental trajectory v2 arrives in A3
            decision=decision.decision,
            fail_mode=decision.fail_mode,
            action_state=action_state,
            capability_id=decision.capability_id,
        )
