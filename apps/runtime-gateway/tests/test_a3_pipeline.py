"""A3 integration: detector/trajectory/risk escalation + async events via pipeline."""
import unittest

from capability_registry import CapabilityRegistry, ToolCapability
from enums import ApprovalMode, Decision, ReasonCode, Sensitivity, SideEffect
from policy_enforcement import RuntimeGatewayPipeline
from risk.precomputed import PrecomputedRiskStore, RiskProfile
from validation import is_valid


def _cap(tool, caps, se, sens, appr=ApprovalMode.NEVER):
    return ToolCapability(tool_id=tool, capabilities=caps, side_effect=se, sensitivity=sens,
                          approval_mode=appr, version="1")


def registry():
    reg = CapabilityRegistry()
    reg.register(_cap("safe_echo", ("mcp.invoke",), SideEffect.NONE, Sensitivity.LOW))
    reg.register(_cap("secret_reader", ("secret.read",), SideEffect.READ, Sensitivity.MEDIUM))
    reg.register(_cap("fs_writer", ("filesystem.write",), SideEffect.WRITE, Sensitivity.MEDIUM))
    reg.register(_cap("net_egress", ("network.egress",), SideEffect.NETWORK, Sensitivity.MEDIUM))
    return reg


def raw(tool, *, args=None, trajectory_id=None, event_id="e1", tenant_id="A"):
    return {"event_id": event_id, "trace_id": "t", "tool_id": tool,
            "arguments": args or {"q": "select 1"}, "trajectory_id": trajectory_id,
            "tenant": {"schema_version": "1.0.0", "tenant_id": tenant_id, "workspace_id": "w",
                       "environment_id": "e", "environment": "production",
                       "identity_id": "i", "identity_type": "service"}}


class TestDetectorEscalation(unittest.TestCase):
    def test_high_detector_escalates_allow_to_sandbox(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw("safe_echo", args={"q": "1' or 1=1 --"}), "mcp")
        self.assertEqual(d.decision, Decision.SANDBOX)
        self.assertIn(ReasonCode.DETECTOR_SQL_INJECTION, d.reason_codes)
        self.assertIn(ReasonCode.DETECTOR_ESCALATION_HIGH, d.reason_codes)

    def test_critical_detector_blocks(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw("safe_echo", args={"c": "x; rm -rf /"}), "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.DETECTOR_ESCALATION_CRITICAL, d.reason_codes)

    def test_benign_stays_allow(self):
        d = RuntimeGatewayPipeline(registry()).process(raw("safe_echo"), "mcp")
        self.assertEqual(d.decision, Decision.ALLOW)


class TestTrajectoryChainViaPipeline(unittest.TestCase):
    def test_sensitive_then_egress_escalates(self):
        p = RuntimeGatewayPipeline(registry())
        p.process(raw("secret_reader", trajectory_id="chain-1", event_id="e1"), "mcp")
        p.process(raw("fs_writer", trajectory_id="chain-1", event_id="e2"), "mcp")
        d = p.process(raw("net_egress", trajectory_id="chain-1", event_id="e3"), "mcp")
        self.assertEqual(d.decision, Decision.SANDBOX)
        self.assertIn(ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS, d.reason_codes)
        self.assertEqual(d.trajectory_version, 3)


class TestPrecomputedRisk(unittest.TestCase):
    def test_high_profile_requires_approval(self):
        store = PrecomputedRiskStore()
        store.publish(RiskProfile(
            subject_type="tool", subject_id="safe_echo", tenant_id="A", environment="production",
            risk_score=0.95, confidence=0.9, source="aegis", version="1",
            generated_at="2026-09-12T00:00:00Z"))
        p = RuntimeGatewayPipeline(registry(), risk=store)
        d = p.process(raw("safe_echo"), "mcp")
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.PRECOMPUTED_RISK_HIGH, d.reason_codes)

    def test_missing_profile_stays_allow(self):
        p = RuntimeGatewayPipeline(registry(), risk=PrecomputedRiskStore())
        self.assertEqual(p.process(raw("safe_echo"), "mcp").decision, Decision.ALLOW)


class TestAsyncEvents(unittest.TestCase):
    def test_learning_event_published_and_valid(self):
        p = RuntimeGatewayPipeline(registry())
        p.process(raw("safe_echo", args={"secret": "shh"}), "mcp")
        events = p.publisher.drain()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertTrue(is_valid(ev, "learning_event"), ev)
        self.assertEqual(ev["kind"], "decision")
        # summary must not leak raw arguments
        self.assertNotIn("shh", str(ev))


if __name__ == "__main__":
    unittest.main()
