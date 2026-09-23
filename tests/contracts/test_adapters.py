"""Source adapters: every ingress shape converges to a valid SecurityEvent."""
import unittest

from adapters import (adapt, agent_framework_adapter, mcp_adapter,
                      message_integration_adapter, sdk_adapter, tool_wrapper_adapter)
from enums import EventSource, ReasonCode


def tenant():
    return {"schema_version": "1.0.0", "tenant_id": "t", "workspace_id": "w",
            "environment_id": "e", "environment": "production",
            "identity_id": "svc", "identity_type": "service"}


class TestMcpAdapter(unittest.TestCase):
    def test_jsonrpc_tools_call(self):
        res = adapt(EventSource.MCP, {
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {"name": "postgres_read", "arguments": {"q": "select 1"},
                       "capability": "database.read", "resource": "crm.customers"}}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "postgres_read")
        self.assertEqual(res.event.event_id, "req-1")
        self.assertEqual(res.event.declared_capability_id, "database.read")
        self.assertEqual(res.event.resource_scope, "crm.customers")

    def test_non_tool_call_methods_are_rejected(self):
        for method in ("tools/list", "initialize", "notifications/message"):
            res = adapt(EventSource.MCP, {"method": method, "params": {}}, tenant())
            self.assertFalse(res.ok)
            self.assertIn(ReasonCode.NORMALIZATION_MALFORMED_INPUT, res.errors)

    def test_flat_shape_still_supported(self):
        res = adapt(EventSource.MCP, {"id": "e1", "tool": "safe_echo",
                                      "arguments": {"q": "x"}}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "safe_echo")


class TestFrameworkAdapters(unittest.TestCase):
    def test_sdk_direct_shape(self):
        res = adapt(EventSource.SDK, {"tool_id": "http_get", "arguments": {"url": "x"},
                                      "declared_capability_id": "net.http",
                                      "resource_scope": "api.example"}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual((res.event.tool_id, res.event.declared_capability_id),
                         ("http_get", "net.http"))

    def test_langchain_style_action(self):
        res = adapt(EventSource.AGENT_FRAMEWORK,
                    {"tool": "search", "tool_input": {"query": "hi"}, "thread_id": "th-9"}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "search")
        self.assertEqual(res.event.trajectory_id, "th-9")

    def test_openai_tool_call_with_json_string_arguments(self):
        res = adapt(EventSource.AGENT_FRAMEWORK,
                    {"function": {"name": "transfer", "arguments": '{"amount": 10}'}}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "transfer")
        self.assertEqual(res.event.arguments, {"amount": 10})

    def test_malformed_json_arguments_are_a_normalization_error(self):
        res = adapt(EventSource.AGENT_FRAMEWORK,
                    {"function": {"name": "t", "arguments": "{not json"}}, tenant())
        self.assertFalse(res.ok)
        self.assertIn(ReasonCode.NORMALIZATION_MALFORMED_INPUT, res.errors)

    def test_tool_wrapper_kwargs(self):
        res = adapt(EventSource.TOOL_WRAPPER, {"name": "write_file",
                                               "kwargs": {"path": "/tmp/x"}}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "write_file")

    def test_message_integration_command(self):
        res = adapt(EventSource.MESSAGE_INTEGRATION,
                    {"command": "deploy", "args": {"env": "prod"}, "channel": "ops"}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.tool_id, "deploy")
        self.assertEqual(res.event.resource_scope, "ops")


class TestAdapterSafety(unittest.TestCase):
    def test_missing_tool_is_rejected_not_crashed(self):
        for source in (EventSource.SDK, EventSource.TOOL_WRAPPER, EventSource.AGENT_FRAMEWORK):
            res = adapt(source, {"arguments": {"x": 1}}, tenant())
            self.assertFalse(res.ok)

    def test_non_dict_payload_and_unknown_source(self):
        self.assertFalse(adapt(EventSource.SDK, ["not", "a", "dict"], tenant()).ok)
        self.assertFalse(adapt("carrier_pigeon", {"tool": "x"}, tenant()).ok)

    def test_invalid_tenant_is_rejected_by_normalization(self):
        res = adapt(EventSource.SDK, {"tool": "x", "arguments": {}}, {"tenant_id": "t"})
        self.assertFalse(res.ok)

    def test_adapter_confers_no_authority_capability_is_passed_through_only(self):
        # A payload can *claim* any capability; the adapter just carries the claim.
        res = adapt(EventSource.SDK, {"tool": "rm", "arguments": {},
                                      "declared_capability_id": "identity.admin"}, tenant())
        self.assertTrue(res.ok)
        self.assertEqual(res.event.declared_capability_id, "identity.admin")  # claim only

    def test_adapters_are_pure_do_not_mutate_input(self):
        payload = {"tool": "x", "arguments": {"a": 1}}
        sdk_adapter(payload, tenant())
        self.assertEqual(payload, {"tool": "x", "arguments": {"a": 1}})


if __name__ == "__main__":
    unittest.main()
