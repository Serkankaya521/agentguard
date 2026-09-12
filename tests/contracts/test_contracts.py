"""Contract tests: schemas are the source of truth for cross-component payloads."""
import unittest

from validation import validate, is_valid, schema_version, load_schema
from serialization import canonical_json, content_hash, redact, to_jsonable


def valid_tenant():
    return {
        "schema_version": "1.0.0",
        "tenant_id": "tenant-A", "workspace_id": "ws-1",
        "environment_id": "env-prod", "environment": "production",
        "identity_id": "svc-42", "identity_type": "service",
    }


class TestSchemasPresentAndVersioned(unittest.TestCase):
    def test_all_a1_contracts_are_v1(self):
        for name in ("tenant_context", "tool_capability", "security_event",
                     "policy_decision", "runtime_decision"):
            self.assertEqual(schema_version(name), "1.0.0", name)
            self.assertIn("$id", load_schema(name), name)


class TestTenantContract(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(is_valid(valid_tenant(), "tenant_context"))

    def test_missing_tenant_id_invalid(self):
        t = valid_tenant(); t.pop("tenant_id")
        self.assertFalse(is_valid(t, "tenant_context"))

    def test_bad_environment_enum_invalid(self):
        t = valid_tenant(); t["environment"] = "prod"  # not an enum value
        self.assertFalse(is_valid(t, "tenant_context"))


class TestToolCapabilityContract(unittest.TestCase):
    def test_valid(self):
        cap = {
            "schema_version": "1.0.0", "tool_id": "postgres_read_table",
            "capabilities": ["database.read"], "resource_patterns": ["crm.*"],
            "side_effect": "read", "data_classes": ["PII"], "sensitivity": "high",
            "environment": "production", "approval_mode": "conditional", "version": "1",
        }
        self.assertTrue(is_valid(cap, "tool_capability"))

    def test_empty_capabilities_invalid(self):
        cap = {
            "schema_version": "1.0.0", "tool_id": "x", "capabilities": [],
            "side_effect": "none", "sensitivity": "low", "approval_mode": "never", "version": "1",
        }
        self.assertFalse(is_valid(cap, "tool_capability"))


class TestSecurityEventContract(unittest.TestCase):
    def test_valid_with_embedded_tenant(self):
        evt = {
            "schema_version": "1.0.0", "event_id": "e1", "trace_id": "t1",
            "occurred_at": "2026-09-12T00:00:00Z", "source": "mcp",
            "action_state": "proposed", "tenant": valid_tenant(),
            "tool_id": "safe_echo", "payload_hash": "sha256:abc",
        }
        self.assertTrue(is_valid(evt, "security_event"))

    def test_missing_tenant_invalid(self):
        evt = {
            "schema_version": "1.0.0", "event_id": "e1", "trace_id": "t1",
            "occurred_at": "2026-09-12T00:00:00Z", "source": "mcp",
            "action_state": "proposed", "tool_id": "safe_echo", "payload_hash": "sha256:abc",
        }
        self.assertFalse(is_valid(evt, "security_event"))

    def test_embedded_tenant_is_validated(self):
        bad = valid_tenant(); bad.pop("identity_id")
        evt = {
            "schema_version": "1.0.0", "event_id": "e1", "trace_id": "t1",
            "occurred_at": "2026-09-12T00:00:00Z", "source": "mcp",
            "action_state": "proposed", "tenant": bad,
            "tool_id": "safe_echo", "payload_hash": "sha256:abc",
        }
        self.assertFalse(is_valid(evt, "security_event"))


class TestSerialization(unittest.TestCase):
    def test_canonical_json_is_key_order_independent(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_content_hash_stable_across_key_order(self):
        self.assertEqual(content_hash({"a": 1, "b": 2}), content_hash({"b": 2, "a": 1}))

    def test_redact_hides_sensitive_keys(self):
        out = redact({"api_key": "sk-secret", "tool": "x", "nested": {"password": "p"}})
        self.assertEqual(out["api_key"], "[REDACTED]")
        self.assertEqual(out["nested"]["password"], "[REDACTED]")
        self.assertEqual(out["tool"], "x")


if __name__ == "__main__":
    unittest.main()
