"""Contract tests: schemas are the source of truth for cross-component payloads."""
import unittest

from validation import CONTRACTS, bundle, validate, is_valid, schema_version, load_schema
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


class TestSchemaBundling(unittest.TestCase):
    """Validators run on inlined schemas: no $ref resolution per request."""

    @staticmethod
    def _refs(node):
        if isinstance(node, dict):
            own = [node["$ref"]] if "$ref" in node else []
            return own + [r for v in node.values() for r in TestSchemaBundling._refs(v)]
        if isinstance(node, list):
            return [r for v in node for r in TestSchemaBundling._refs(v)]
        return []

    def test_every_contract_bundles_without_refs(self):
        for name in CONTRACTS:
            self.assertEqual(self._refs(bundle(load_schema(name))), [], name)

    def test_cross_contract_and_local_refs_still_enforced(self):
        # compiled_policy -> policy#/$defs/ruleset -> #/$defs/decision (local to policy)
        ruleset = bundle(load_schema("compiled_policy"))["properties"]["ruleset"]
        self.assertNotIn("$id", ruleset)
        self.assertIn("properties", ruleset)

    def test_ref_siblings_are_kept(self):
        schema = {"$id": "urn:t", "$defs": {"s": {"type": "string"}},
                  "properties": {"x": {"$ref": "#/$defs/s", "maxLength": 2}}}
        x = bundle(schema)["properties"]["x"]
        self.assertEqual(x, {"allOf": [{"type": "string"}, {"maxLength": 2}]})

    def test_recursive_ref_is_rejected(self):
        schema = {"$id": "urn:t", "$defs": {"n": {"properties": {"next": {"$ref": "#/$defs/n"}}}},
                  "$ref": "#/$defs/n"}
        with self.assertRaises(ValueError):
            bundle(schema)


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
