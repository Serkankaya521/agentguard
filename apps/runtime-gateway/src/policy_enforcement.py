"""Runtime gateway pipeline (Sprint A3: detectors, trajectory, risk, events).

Sequence (master arch 5 / task plan 5):
  (cached compiled policy) normalize -> validate context
  -> capability lookup (cache + circuit breaker)
  -> deterministic detectors -> incremental trajectory update -> precomputed risk
  -> evaluate compiled policy (signals may escalate ALLOW) -> PEP
  -> RuntimeDecision (cache_source, latency, trajectory_version)
  -> async LearningEvent publish (off hot path)

Deferred beyond A3 (explicit seams): real broker/DLQ infra and AEGIS profile
production (Developer B / worker); behavioral detector; full recomputation worker.
"""
from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Optional

from config import RUNTIME_VERSION
from context import validate_context
from normalization import normalize

from cache import TieredCache, make_key
from hot_path import latency_budget
from hot_path.circuit_breaker import CircuitBreaker
from hot_path.event_publisher import AsyncEventPublisher
from hot_path.analytics_publisher import AnalyticsEventPublisher
from policy.artifact_loader import ActivePolicyProvider
from risk.precomputed import PrecomputedRiskStore
from trajectory.incremental_state import TrajectoryStore

from bounded import DetectorRunner, DetectorSignal, max_severity  # packages/detectors/src
from runtime import default_detectors  # packages/detectors/src
from egress import scan_response, evaluate_egress, SHADOW, MASK  # packages/detectors/src (B-R2/B-R3/B-R4 egress)

from capability_registry import CapabilityRegistry, CapabilityResolution  # packages/policy/src
from evaluator import evaluate  # packages/policy/src (pure)
from pep import EnforcementOutcome, PolicyEnforcementPoint  # packages/policy/src

from decisions import PolicyDecision, RuntimeDecision  # packages/domain/src
from enums import ActionState, CacheSource, Decision, DetectorSeverity, FailMode, ReasonCode

_CACHE_RANK = {CacheSource.NONE: 0, CacheSource.L1: 1, CacheSource.L2: 2, CacheSource.COMPUTED: 3}
_ESCALATING = (DetectorSeverity.HIGH, DetectorSeverity.CRITICAL)


def _worst(a: CacheSource, b: CacheSource) -> CacheSource:
    return a if _CACHE_RANK[a] >= _CACHE_RANK[b] else b


class RuntimeGatewayPipeline:
    """Stateless orchestrator (trajectory state lives in a bounded external store)."""

    def __init__(
        self,
        registry: Optional[CapabilityRegistry] = None,
        *,
        cache: Optional[TieredCache] = None,
        provider: Optional[ActivePolicyProvider] = None,
        breaker: Optional[CircuitBreaker] = None,
        detectors: Optional[DetectorRunner] = None,
        trajectory: Optional[TrajectoryStore] = None,
        risk: Optional[PrecomputedRiskStore] = None,
        publisher: Optional[AsyncEventPublisher] = None,
        analytics_publisher: Optional[AnalyticsEventPublisher] = None,
        risk_budget=None,
        budget_us: int = latency_budget.GLOBAL_BUDGET_US,
    ) -> None:
        self._registry = registry or CapabilityRegistry()
        self._cache = cache or TieredCache()
        self._provider = provider or ActivePolicyProvider(cache=self._cache)
        self._pep = PolicyEnforcementPoint()
        self._breaker = breaker or CircuitBreaker()
        self._detectors = detectors or DetectorRunner(default_detectors())
        self._trajectory = trajectory or TrajectoryStore()
        self._risk = risk or PrecomputedRiskStore()
        self._publisher = publisher or AsyncEventPublisher()
        self._analytics_publisher = analytics_publisher or AnalyticsEventPublisher()
        self._risk_budget = risk_budget
        self._budget_us = budget_us

    @property
    def publisher(self) -> AsyncEventPublisher:
        return self._publisher

    @property
    def analytics_publisher(self) -> AnalyticsEventPublisher:
        return self._analytics_publisher

    def process(self, raw: object, source: object) -> RuntimeDecision:
        deadline = latency_budget.start(self._budget_us)
        ruleset, policy_src, _ = self._provider.get_active()

        result = normalize(raw, source)
        if not result.ok or result.event is None:
            return self._finalize(
                deadline, self._safe_tenant_id(raw), "unknown", "unknown",
                self._block(ruleset, tuple(result.errors or (ReasonCode.NORMALIZATION_SCHEMA_INVALID,))),
                ActionState.BLOCKED, CacheSource.COMPUTED, 0)

        event = result.event

        context_errors = validate_context(event.tenant)
        if context_errors:
            return self._finalize(
                deadline, event.tenant.tenant_id, event.event_id, event.trace_id,
                self._block(ruleset, tuple(context_errors)),
                ActionState.BLOCKED, policy_src, 0)

        # Capability lookup: cache + circuit breaker. Dependency failure -> fail mode.
        cap_key = make_key("cap", "reg", event.tool_id, event.declared_capability_id or "-")
        try:
            resolution, cap_src = self._cache.get_or_compute(
                cap_key,
                lambda: self._breaker.call(
                    lambda: self._registry.resolve(event.tool_id, event.declared_capability_id)))
            dependency_ok = True
        except Exception:
            resolution = CapabilityResolution(
                known=False, record=None, capability_id=event.declared_capability_id, mismatch=False)
            cap_src = CacheSource.COMPUTED
            dependency_ok = False

        # Deterministic detectors (bounded, hot-path safe).
        det_signals = self._detectors.run(event.arguments, event.resource_scope, event.tool_id)
        det_severity = max_severity([s for s in det_signals])
        det_reasons = tuple(dict.fromkeys(
            s.reason_code for s in det_signals if s.severity in _ESCALATING))

        # Incremental trajectory (only when a trajectory is identified).
        trajectory_version = 0
        traj_signals: list[DetectorSignal] = []
        if event.trajectory_id:
            state, traj_signals = self._trajectory.update(
                tenant_id=event.tenant.tenant_id, trajectory_id=event.trajectory_id,
                event_id=event.event_id, capability_id=resolution.capability_id)
            trajectory_version = state.version
        chain_egress = any(
            s.reason_code == ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS for s in traj_signals)

        # Precomputed AEGIS risk (read-only; fallback on stale/missing).
        precomputed_high = self._precomputed_high(event)

        decision = evaluate(
            ruleset, environment=event.tenant.environment, resolution=resolution,
            resource_scope=event.resource_scope, dependency_ok=dependency_ok,
            detector_severity=det_severity, detector_reasons=det_reasons,
            chain_egress=chain_egress, precomputed_high=precomputed_high)
        if self._risk_budget is not None:
            over = self._risk_budget.record_and_check(
                tenant_id=event.tenant.tenant_id, identity_id=event.tenant.identity_id,
                risk=decision.risk_score)
            if over and decision.decision == Decision.ALLOW:
                decision = replace(decision, decision=Decision.REQUIRE_APPROVAL,
                                   reason_codes=(ReasonCode.RISK_BUDGET_EXCEEDED,) + decision.reason_codes)
        outcome: EnforcementOutcome = self._pep.enforce(decision)

        runtime_decision = self._finalize(
            deadline, event.tenant.tenant_id, event.event_id, event.trace_id,
            decision, outcome.action_state, _worst(policy_src, cap_src), trajectory_version)

        # Async learning + analytics events (off the hot path, after latency is
        # recorded, non-blocking). A forwarder drains analytics to security.events.
        self._publisher.publish_decision(event, runtime_decision)
        self._analytics_publisher.publish_event(event, runtime_decision)
        return runtime_decision

    def scan_egress(self, response: str, *, known_secrets=(), request: str = "") -> list[DetectorSignal]:
        """B-R2 egress pass: scan a tool/agent response for secret leakage and return
        signals. Deterministic/bounded, hot-path safe. The shadow/enforce decision and
        the per-policy egress_secret_guard flag are B-R3/B-R4; this only detects."""
        return scan_response(response, known_secrets, request)

    def guard_egress(self, response: str, *, known_secrets=(), request: str = "",
                     mode: str = SHADOW, action: str = MASK, event=None):
        """Egress guard. Scan the response; shadow (B-R3) records a would_block event off the hot
        path and passes traffic unchanged; enforce (B-R4) masks the secret or stops the response.
        `mode` (off|shadow|enforce) and `action` (mask|stop) are per-policy flags whose schema/
        storage is Dev B; defaults shadow/mask. Returns the EgressGuardResult (result.response is
        the response to return to the caller)."""
        result = evaluate_egress(response, known_secrets, request, mode, action)
        if result.would_block:
            self._publisher.publish_egress_shadow(event, result)
        return result

    # --- helpers -----------------------------------------------------------
    def _precomputed_high(self, event) -> bool:
        for subject_type, subject_id in (("agent", event.tenant.agent_id), ("tool", event.tool_id)):
            if subject_id:
                if self._risk.lookup(subject_type, subject_id, event.tenant.tenant_id).is_high:
                    return True
        return False

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
            policy_hash=ruleset.policy_hash, capability_id=None)

    def _finalize(
        self, deadline, tenant_id: str, event_id: str, trace_id: str,
        decision: PolicyDecision, action_state: ActionState, cache_source: CacheSource,
        trajectory_version: int,
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
            trajectory_version=trajectory_version,
            decision=decision.decision,
            fail_mode=decision.fail_mode,
            action_state=action_state,
            capability_id=decision.capability_id)
