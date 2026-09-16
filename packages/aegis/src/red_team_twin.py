"""AgentGuard-vs-AgentGuard (master arch 17; task plan 24).

A twin that runs adversarial scenarios against the REAL security components and
asserts the defenses hold. Runs only in an authorized test environment with a
bounded budget. Critical scenarios are wired into the release gate (see tests).
Each scenario returns whether the defense held.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from capability_registry import CapabilityRegistry, ToolCapability
from decisions import RuntimeDecision
from enums import (
    ActionState, ApprovalMode, CacheSource, Decision, FailMode, IdentityType,
    Environment, ReasonCode, Sensitivity, SideEffect,
)
from policy_enforcement import RuntimeGatewayPipeline
from security_event import SecurityEvent
from tenant import TenantContext, SCHEMA_VERSION as TC_VER

from cache import InvalidationConsumer, L1Cache, make_key
from execution_gate import DecisionSigner, ExecutionGate
from risk.precomputed import PrecomputedRiskStore, RiskProfile
from bounded import DetectorRunner
from runtime import default_detectors
import integrity  # packages/evidence/src
from risk_profiles import RiskProfilePublisher
from execution.kill_switch import KillSwitch
from execution.safety_budget import RulesOfEngagement, SafetyBudget
from jobs.red_team import RedTeamCampaign
from governance import GovernancePipeline, GovernanceViolation, Proposal


@dataclass(frozen=True)
class ScenarioResult:
    scenario: str
    defended: bool
    detail: str


def _registry():
    reg = CapabilityRegistry()
    reg.register(ToolCapability(tool_id="safe_echo", capabilities=("mcp.invoke",),
                                side_effect=SideEffect.NONE, sensitivity=Sensitivity.LOW,
                                approval_mode=ApprovalMode.NEVER, version="1"))
    return reg


def _raw(tool="safe_echo", *, tenant="A", args=None, declared=None, env="production"):
    return {"event_id": "e1", "trace_id": "t1", "tool_id": tool, "arguments": args or {},
            "declared_capability_id": declared,
            "tenant": {"schema_version": "1.0.0", "tenant_id": tenant, "workspace_id": "w",
                       "environment_id": "e", "environment": env,
                       "identity_id": "i", "identity_type": "service"}}


def _event(event_id="e1", tenant="A", tool="safe_echo"):
    return SecurityEvent(event_id=event_id, trace_id="t", occurred_at="2026-09-12T00:00:00Z",
                         source=__import__("enums").EventSource.MCP,
                         action_state=ActionState.PROPOSED,
                         tenant=TenantContext(tenant_id=tenant, workspace_id="w", environment_id="e",
                                              environment=Environment.PRODUCTION, identity_id="i",
                                              identity_type=IdentityType.SERVICE),
                         tool_id=tool, payload_hash="sha256:x")


def _decision(dec=Decision.ALLOW, event_id="e1", tenant="A"):
    return RuntimeDecision(decision_id="d1", tenant_id=tenant, event_id=event_id, trace_id="t",
                           policy_version="builtin/1.0.0", policy_hash="sha256:p", runtime_version="rt",
                           risk_score=0.1, reason_codes=(ReasonCode.ALLOWED_LOW_RISK,),
                           cache_source=CacheSource.COMPUTED, latency_us=1, trajectory_version=0,
                           decision=dec, fail_mode=FailMode.FAIL_CLOSED,
                           action_state=ActionState.PROPOSED, capability_id="mcp.invoke")


class TwinHarness:
    KEY = "twin-key"

    def policy_bypass(self):
        d = RuntimeGatewayPipeline(_registry()).process(_raw("unknown_tool"), "mcp")
        return d.decision != Decision.ALLOW

    def capability_spoofing(self):
        d = RuntimeGatewayPipeline(_registry()).process(_raw(declared="secret.read"), "mcp")
        return d.decision == Decision.BLOCK and ReasonCode.CAPABILITY_MISMATCH in d.reason_codes

    def tenant_context_confusion(self):
        p = RuntimeGatewayPipeline(_registry())
        a = p.process(_raw(tenant="A"), "mcp"); b = p.process(_raw(tenant="B"), "mcp")
        keys_isolated = make_key("cap", "1", "t", tenant_id="A") != make_key("cap", "1", "t", tenant_id="B")
        return a.tenant_id == "A" and b.tenant_id == "B" and keys_isolated

    def approval_replay(self):
        gate = ExecutionGate(self.KEY)
        sd = DecisionSigner(self.KEY).sign(_decision())
        first = gate.authorize(sd, _event())
        second = gate.authorize(sd, _event())
        return first.permitted and not second.permitted and ReasonCode.EXEC_REPLAY_DETECTED in second.reason_codes

    def detector_evasion(self):
        d = RuntimeGatewayPipeline(_registry()).process(_raw(args={"q": "1' or 1=1 --"}), "mcp")
        return d.decision != Decision.ALLOW  # escalated

    def cache_poisoning_staleness(self):
        t = [0.0]
        store = PrecomputedRiskStore(clock=lambda: t[0])
        store.publish(RiskProfile("tool", "safe_echo", "A", "production", 0.99, 0.9,
                                  "aegis", "1", "2026-09-12T00:00:00Z"), ttl_s=10)
        t[0] = 100.0
        stale = store.lookup("tool", "safe_echo", "A")
        l1 = L1Cache(); l1.set("cap:t1", 1)
        InvalidationConsumer(l1).process({"schema_version": "1.0.0", "event_id": "iv1",
            "sequence": 0, "namespace": "cap", "keys": ["t1"], "issued_at": "2026-09-12T00:00:00Z"})
        return (not stale.is_high) and (not l1.get("cap:t1")[1])

    def event_reordering_duplication(self):
        from trajectory.incremental_state import TrajectoryStore
        s = TrajectoryStore()
        s.update(tenant_id="A", trajectory_id="x", event_id="e1", capability_id="secret.read")
        _, sig = s.update(tenant_id="A", trajectory_id="x", event_id="e1", capability_id="secret.read")
        return any(x.reason_code == ReasonCode.TRAJECTORY_DUPLICATE_EVENT for x in sig)

    def evidence_tampering(self):
        rec = {"schema_version": "1.0.0", "evidence_id": "ev1", "tenant_id": "A",
               "event_id": "e1", "action_state": "executed",
               "sources": [{"kind": "resource_mutation", "ref": "sha256:a"}],
               "created_at": "2026-09-12T00:00:00Z"}
        rec["integrity_hash"] = integrity.content_hash(rec)
        ok_before = integrity.verify(rec)[0]
        rec["sources"][0]["ref"] = "sha256:TAMPER"
        return ok_before and not integrity.verify(rec)[0]

    def risk_profile_manipulation(self):
        try:
            RiskProfilePublisher().publish({"schema_version": "1.0.0", "subject_type": "tool"})
            return False
        except ValueError:
            return True

    def kill_switch_bypass(self):
        ks = KillSwitch(); ks.trip(actor="op", global_=True)
        roe = RulesOfEngagement(campaign_id="c1", authorized_targets=frozenset({"app.test"}),
                                environment="test", kill_switch_owner="op")
        r = RedTeamCampaign().run(target="app.test", safety_budget=SafetyBudget(roe),
                                  kill_switch=ks, tenant_id="A")
        return r.killed and r.executed == 0

    def governance_bypass(self):
        gp = GovernancePipeline(signing_key=self.KEY)
        prop = Proposal(proposal_id="p1", kind="detector", content={})
        blocked_promote = blocked_selfdeploy = False
        try:
            gp.promote(prop)  # not signed/approved
        except GovernanceViolation:
            blocked_promote = True
        try:
            gp.aegis_attempt_deploy(prop)
        except GovernanceViolation:
            blocked_selfdeploy = True
        return blocked_promote and blocked_selfdeploy

    def latency_exhaustion_redos(self):
        start = time.perf_counter()
        DetectorRunner(default_detectors()).run({"x": "a" * 5_000_000}, None, "t")
        return (time.perf_counter() - start) < 0.5  # bounded, no catastrophic blowup

    def run_all(self) -> list[ScenarioResult]:
        scenarios = [
            ("policy_bypass", self.policy_bypass),
            ("capability_spoofing", self.capability_spoofing),
            ("tenant_context_confusion", self.tenant_context_confusion),
            ("approval_replay", self.approval_replay),
            ("detector_evasion", self.detector_evasion),
            ("cache_poisoning_staleness", self.cache_poisoning_staleness),
            ("event_reordering_duplication", self.event_reordering_duplication),
            ("evidence_tampering", self.evidence_tampering),
            ("risk_profile_manipulation", self.risk_profile_manipulation),
            ("kill_switch_bypass", self.kill_switch_bypass),
            ("governance_bypass", self.governance_bypass),
            ("latency_exhaustion_redos", self.latency_exhaustion_redos),
        ]
        results = []
        for name, fn in scenarios:
            try:
                defended = bool(fn())
                results.append(ScenarioResult(name, defended, "ok" if defended else "DEFENSE FAILED"))
            except Exception as exc:  # a scenario harness error is a failed defense
                results.append(ScenarioResult(name, False, f"error: {type(exc).__name__}: {exc}"))
        return results
