"""A7 finish: risk budget, behavioral detector, runtime evidence/mcp/telemetry/main, worker jobs."""
import types
import unittest

from risk_budget import RiskBudgetPolicy, RiskBudgetStore
from behavioral import BehaviorBaseline, BehavioralAnomalyDetector
from enums import (ApprovalMode, Decision, DetectorSeverity, FindingState, ReasonCode,
                   Sensitivity, SideEffect)
from capability_registry import CapabilityRegistry, ToolCapability
from policy_enforcement import RuntimeGatewayPipeline
from evidence_capture import RuntimeEvidenceCapture
from mcp.gateway import McpGateway
from telemetry import TelemetryEmitter
import main as gateway_main
from validation import is_valid

from capture import EvidenceValidator
from jobs.learning import LearningJob
from jobs.regression import RegressionJob
from jobs.trajectory_recompute import TrajectoryRecomputeJob
from memory.strategic import StrategicMemory
from regression import RegressionEngine
from trajectory.incremental_state import TrajectoryStore


def _reg():
    r = CapabilityRegistry()
    r.register(ToolCapability(tool_id="safe_echo", capabilities=("mcp.invoke",),
                              side_effect=SideEffect.NONE, sensitivity=Sensitivity.LOW,
                              approval_mode=ApprovalMode.NEVER, version="1"))
    return r


def _raw(tenant="A"):
    return {"event_id": "e1", "trace_id": "t1", "tool_id": "safe_echo", "arguments": {"q": "select 1"},
            "tenant": {"schema_version": "1.0.0", "tenant_id": tenant, "workspace_id": "w",
                       "environment_id": "e", "environment": "production",
                       "identity_id": "svc-1", "identity_type": "service"}}


class TestRiskBudget(unittest.TestCase):
    def test_store_flags_over_budget(self):
        s = RiskBudgetStore(RiskBudgetPolicy(max_cumulative_risk=0.15, high_risk_threshold=0.9))
        self.assertFalse(s.record_and_check(tenant_id="A", identity_id="i", risk=0.1))
        self.assertTrue(s.record_and_check(tenant_id="A", identity_id="i", risk=0.1))

    def test_pipeline_escalates_over_budget(self):
        store = RiskBudgetStore(RiskBudgetPolicy(max_cumulative_risk=0.15, high_risk_threshold=0.9))
        p = RuntimeGatewayPipeline(_reg(), risk_budget=store)
        self.assertEqual(p.process(_raw(), "mcp").decision, Decision.ALLOW)
        d = p.process(_raw(), "mcp")
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.RISK_BUDGET_EXCEEDED, d.reason_codes)


class TestBehavioral(unittest.TestCase):
    def test_no_baseline_no_signal(self):
        self.assertEqual(BehavioralAnomalyDetector().detect(
            capability_id="x", baseline=None), [])

    def test_unexpected_capability_and_rate(self):
        b = BehaviorBaseline("i", expected_capabilities=frozenset({"mcp.invoke"}), max_rate_per_window=5)
        sigs = BehavioralAnomalyDetector().detect(capability_id="secret.read", baseline=b, recent_count=10)
        reasons = {s.reason_code for s in sigs}
        self.assertIn(ReasonCode.DETECTOR_BEHAVIORAL_ANOMALY, reasons)
        self.assertTrue(any(s.severity == DetectorSeverity.HIGH for s in sigs))


class TestRuntimeEvidenceCapture(unittest.TestCase):
    def test_from_decision_is_valid_and_backed(self):
        d = RuntimeGatewayPipeline(_reg()).process(_raw(), "mcp")
        event = types.SimpleNamespace(payload_hash="sha256:x")
        rec = RuntimeEvidenceCapture("k").from_decision(event, d)
        self.assertTrue(is_valid(rec.to_dict(), "evidence"))
        res = EvidenceValidator("k").validate(rec)
        self.assertTrue(res.integrity_ok and res.evidence_backed)


class TestMcpAndTelemetryAndMain(unittest.TestCase):
    def test_mcp_normalizes(self):
        res = McpGateway().handle(
            {"id": "e1", "tool": "safe_echo", "arguments": {"q": "select 1"}},
            _raw()["tenant"])
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "safe_echo")

    def test_telemetry_emit_drain_no_pii(self):
        d = RuntimeGatewayPipeline(_reg()).process(_raw(), "mcp")
        t = TelemetryEmitter(); t.emit(d)
        out = t.drain()
        self.assertEqual(len(out), 1)
        self.assertNotIn("select 1", str(out))

    def test_gateway_main_handle(self):
        p = gateway_main.create_gateway(_reg())
        payload = gateway_main.handle(p, _raw(), "http")
        self.assertTrue(is_valid(payload, "runtime_decision"))


class TestWorkerJobs(unittest.TestCase):
    def test_learning_job(self):
        sm = StrategicMemory()
        job = LearningJob(sm)
        self.assertEqual(job.run_hot([{"architecture": "mcp", "technique": "t", "score": 0.8}]), 1)
        self.assertTrue(sm.established(None))
        props = job.run_warm([{"label": "sqli", "samples": []}], [{"tighten": True}])
        self.assertEqual({p.kind for p in props}, {"detector", "policy"})

    def test_regression_job(self):
        eng = RegressionEngine()
        case = eng.register({"schema_version": "1.0.0", "finding_id": "f1", "tenant_id": "A",
                             "state": FindingState.RESOLVED_VERIFIED.value, "root_cause": "rc",
                             "successful_mutations": ["x"]})
        res = RegressionJob().run(eng, [case], defense=lambda p: True)
        self.assertTrue(res[0]["passed"])

    def test_trajectory_recompute_job(self):
        store = TrajectoryStore()
        state = TrajectoryRecomputeJob().recompute(store, tenant_id="A", trajectory_id="x", events=[
            {"event_id": "e1", "capability_id": "secret.read"},
            {"event_id": "e2", "capability_id": "filesystem.write"},
            {"event_id": "e3", "capability_id": "network.egress"}])
        self.assertEqual(state.version, 3)
        self.assertTrue(state.saw_sensitive_read)


if __name__ == "__main__":
    unittest.main()
