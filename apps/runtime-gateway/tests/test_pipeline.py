"""Runtime gateway pipeline tests: the A1 security behaviors."""
import unittest

from capability_registry import CapabilityRegistry, ToolCapability
from context import validate_context
from enums import (
    ActionState, ApprovalMode, CacheSource, Decision, Environment, FailMode,
    IdentityType, ReasonCode, Sensitivity, SideEffect,
)
from pdp import PolicyDecisionPoint
from policy_enforcement import RuntimeGatewayPipeline
from tenant import TenantContext
from validation import is_valid
from serialization import to_jsonable


def registry():
    reg = CapabilityRegistry()
    reg.register(ToolCapability(
        tool_id="safe_echo", capabilities=("mcp.invoke",), side_effect=SideEffect.NONE,
        sensitivity=Sensitivity.LOW, approval_mode=ApprovalMode.NEVER, version="1",
        fail_open_allowed=True))
    reg.register(ToolCapability(
        tool_id="postgres_read_table", capabilities=("database.read",),
        side_effect=SideEffect.READ, sensitivity=Sensitivity.HIGH,
        approval_mode=ApprovalMode.CONDITIONAL, version="1",
        resource_patterns=("crm.*",), data_classes=("PII",)))
    reg.register(ToolCapability(
        tool_id="payment_charge", capabilities=("payment.execute",),
        side_effect=SideEffect.EXECUTE, sensitivity=Sensitivity.CRITICAL,
        approval_mode=ApprovalMode.ALWAYS, version="1", resource_patterns=("*",)))
    return reg


def raw_event(tool_id, *, env="production", tenant_id="tenant-A",
              declared=None, resource_scope=None, action_state="proposed", drop_tenant_id=False):
    tenant = {
        "schema_version": "1.0.0", "tenant_id": tenant_id, "workspace_id": "ws-1",
        "environment_id": "env-x", "environment": env,
        "identity_id": "svc-42", "identity_type": "service",
    }
    if drop_tenant_id:
        tenant.pop("tenant_id")
    return {
        "event_id": "e1", "trace_id": "t1", "tool_id": tool_id, "tenant": tenant,
        "declared_capability_id": declared, "resource_scope": resource_scope,
        "action_state": action_state, "arguments": {"q": "select 1"},
    }


class TestUnknownCapability(unittest.TestCase):
    def test_unknown_tool_blocked_in_production(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("mystery_tool"), "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.BLOCKED_UNKNOWN_CAPABILITY_PROD, d.reason_codes)
        self.assertEqual(d.action_state, ActionState.BLOCKED)

    def test_unknown_tool_approval_in_dev(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("mystery_tool", env="development"), "mcp")
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.APPROVAL_REQUIRED_UNKNOWN_CAPABILITY, d.reason_codes)


class TestCapabilityEnforcement(unittest.TestCase):
    def test_low_risk_allowed(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("safe_echo"), "mcp")
        self.assertEqual(d.decision, Decision.ALLOW)
        self.assertEqual(d.action_state, ActionState.PROPOSED)  # gate not run -> not EXECUTED
        self.assertEqual(d.capability_id, "mcp.invoke")

    def test_capability_spoofing_blocked(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw_event("safe_echo", declared="secret.read"), "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.CAPABILITY_MISMATCH, d.reason_codes)

    def test_resource_scope_violation_blocked(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw_event("postgres_read_table", resource_scope="hr.salaries"), "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.RESOURCE_SCOPE_VIOLATION, d.reason_codes)

    def test_in_scope_conditional_high_requires_approval(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw_event("postgres_read_table", resource_scope="crm.customers"), "mcp")
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.APPROVAL_REQUIRED_CONDITIONAL, d.reason_codes)

    def test_approval_always(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw_event("payment_charge", resource_scope="acct-1"), "mcp")
        self.assertEqual(d.decision, Decision.REQUIRE_APPROVAL)
        self.assertIn(ReasonCode.APPROVAL_REQUIRED_ALWAYS, d.reason_codes)


class TestContextValidation(unittest.TestCase):
    def test_missing_tenant_id_rejected_at_normalization(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("safe_echo", drop_tenant_id=True), "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertEqual(d.action_state, ActionState.BLOCKED)
        self.assertEqual(d.fail_mode, FailMode.FAIL_CLOSED)

    def test_validate_context_reports_missing_fields(self):
        tc = TenantContext(
            tenant_id="", workspace_id="ws", environment_id="env",
            environment=Environment.PRODUCTION, identity_id="id",
            identity_type=IdentityType.SERVICE)
        self.assertIn(ReasonCode.CONTEXT_MISSING_TENANT, validate_context(tc))

    def test_malformed_input_is_not_a_finding(self):
        d = RuntimeGatewayPipeline(registry()).process("not-a-dict", "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.NORMALIZATION_MALFORMED_INPUT, d.reason_codes)


class TestFailMode(unittest.TestCase):
    def test_fail_closed_capability_blocks_on_dependency_failure(self):
        reg = registry()
        res = reg.resolve("payment_charge", None)
        d = PolicyDecisionPoint().decide(
            environment=Environment.PRODUCTION, resolution=res,
            resource_scope="acct-1", dependency_ok=False)
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertEqual(d.fail_mode, FailMode.FAIL_CLOSED)
        self.assertIn(ReasonCode.FAIL_CLOSED_DEPENDENCY, d.reason_codes)

    def test_fail_open_low_risk_allows_on_dependency_failure(self):
        reg = registry()
        res = reg.resolve("safe_echo", None)
        d = PolicyDecisionPoint().decide(
            environment=Environment.PRODUCTION, resolution=res,
            resource_scope=None, dependency_ok=False)
        self.assertEqual(d.decision, Decision.ALLOW)
        self.assertEqual(d.fail_mode, FailMode.FAIL_OPEN)
        self.assertIn(ReasonCode.FAIL_OPEN_POLICY, d.reason_codes)


class TestDeterminismAndMetadata(unittest.TestCase):
    def test_decisions_are_deterministic(self):
        p = RuntimeGatewayPipeline(registry())
        a = p.process(raw_event("postgres_read_table", resource_scope="crm.customers"), "mcp")
        b = p.process(raw_event("postgres_read_table", resource_scope="crm.customers"), "mcp")
        self.assertEqual((a.decision, a.reason_codes, a.risk_score, a.fail_mode, a.capability_id),
                         (b.decision, b.reason_codes, b.risk_score, b.fail_mode, b.capability_id))

    def test_runtime_decision_is_schema_valid_and_has_metadata(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("safe_echo"), "mcp")
        payload = to_jsonable(d)
        self.assertTrue(is_valid(payload, "runtime_decision"), payload)
        for f in ("decision_id", "policy_version", "policy_hash", "runtime_version",
                  "cache_source", "trace_id", "tenant_id"):
            self.assertTrue(payload[f], f)
        self.assertEqual(payload["cache_source"], CacheSource.COMPUTED.value)
        self.assertGreaterEqual(payload["latency_us"], 0)

    def test_tenant_id_comes_from_validated_context(self):
        d = RuntimeGatewayPipeline(registry()).process(
            raw_event("safe_echo", tenant_id="tenant-Z"), "mcp")
        self.assertEqual(d.tenant_id, "tenant-Z")

    def test_no_arguments_leak_into_decision(self):
        d = RuntimeGatewayPipeline(registry()).process(raw_event("safe_echo"), "mcp")
        blob = to_jsonable(d)
        self.assertNotIn("arguments", blob)
        self.assertNotIn("select 1", str(blob))


if __name__ == "__main__":
    unittest.main()
