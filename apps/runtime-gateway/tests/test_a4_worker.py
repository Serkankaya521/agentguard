"""Deep-analysis worker: produces profiles/graph/memory only (learning != privilege),
and closes the AEGIS-producer -> runtime-consumer precomputed-risk loop."""
import unittest

from jobs.deep_analysis import DeepAnalysisJob
from memory.episodic import EpisodicMemory
from repository import GraphRepository
from risk_profiles import RiskProfilePublisher
from risk.precomputed import PrecomputedRiskStore, RiskProfile
from capability_registry import CapabilityRegistry, ToolCapability
from enums import ApprovalMode, Decision, ReasonCode, Sensitivity, SideEffect
from policy_enforcement import RuntimeGatewayPipeline
from validation import is_valid


def learning_event(tool_id, risk, tenant="A"):
    return {"schema_version": "1.0.0", "event_id": f"le-{tool_id}", "trace_id": "t",
            "tenant_id": tenant, "kind": "decision", "priority": 3,
            "occurred_at": "2026-09-12T00:00:00Z", "payload_ref": None,
            "summary": {"tool_id": tool_id, "environment": "production",
                        "risk_score": risk, "capability_id": "mcp.invoke", "decision": "ALLOW"}}


class TestDeepAnalysisWorker(unittest.TestCase):
    def test_publishes_profile_and_builds_graph(self):
        published = []
        job = DeepAnalysisJob(episodic=EpisodicMemory(), graph_repo=GraphRepository(),
                              risk_publisher=RiskProfilePublisher(sink=published.append))
        result = job.analyze_learning_events(
            [learning_event("safe_echo", 0.9), learning_event("safe_echo", 0.3),
             learning_event("low_tool", 0.1)])
        self.assertEqual(result["profiles_published"], 1)  # only safe_echo (max 0.9) is high
        self.assertGreaterEqual(result["graph_nodes"], 2)
        self.assertTrue(is_valid(published[0], "risk_profile"))
        self.assertEqual(published[0]["subject_id"], "safe_echo")

    def test_producer_to_consumer_risk_loop(self):
        store = PrecomputedRiskStore()
        def sink(profile: dict):
            store.publish(RiskProfile(
                subject_type=profile["subject_type"], subject_id=profile["subject_id"],
                tenant_id=profile["tenant_id"], environment=profile["environment"],
                risk_score=profile["risk_score"], confidence=profile["confidence"],
                source=profile["source"], version=profile["version"],
                generated_at=profile["generated_at"],
                reason_codes=tuple(profile.get("reason_codes", ()))))
        job = DeepAnalysisJob(episodic=EpisodicMemory(), graph_repo=GraphRepository(),
                              risk_publisher=RiskProfilePublisher(sink=sink))
        job.analyze_learning_events([learning_event("safe_echo", 0.95)])

        reg = CapabilityRegistry()
        reg.register(ToolCapability(tool_id="safe_echo", capabilities=("mcp.invoke",),
                                    side_effect=SideEffect.NONE, sensitivity=Sensitivity.LOW,
                                    approval_mode=ApprovalMode.NEVER, version="1"))
        pipe = RuntimeGatewayPipeline(reg, risk=store)
        raw = {"event_id": "e", "trace_id": "t", "tool_id": "safe_echo", "arguments": {},
               "tenant": {"schema_version": "1.0.0", "tenant_id": "A", "workspace_id": "w",
                          "environment_id": "e", "environment": "production",
                          "identity_id": "i", "identity_type": "service"}}
        d = pipe.process(raw, "mcp")
        # AEGIS-published risk now escalates the runtime decision (async -> cache -> runtime).
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.PRECOMPUTED_RISK_HIGH, d.reason_codes)


if __name__ == "__main__":
    unittest.main()
