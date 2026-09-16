"""Developer B integration surface: shared contracts present, versioned, loadable."""
import unittest

from validation import CONTRACTS, load_schema, schema_version

IMPLEMENTED = [
    "tenant_context", "tool_capability", "security_event", "policy_decision",
    "runtime_decision", "policy", "compiled_policy", "cache_invalidation_event",
    "risk_profile", "learning_event", "evidence", "finding",
    "approval_request", "approval_decision", "job_envelope",
]


class TestIntegrationSurface(unittest.TestCase):
    def test_all_implemented_contracts_v1_and_loadable(self):
        for name in IMPLEMENTED:
            self.assertIn(name, CONTRACTS, name)
            self.assertEqual(schema_version(name), "1.0.0", name)
            self.assertIn("$id", load_schema(name), name)

    def test_developer_b_contracts_are_now_public(self):
        for name in ("approval_request", "approval_decision", "job_envelope"):
            self.assertIn(name, CONTRACTS)


if __name__ == "__main__":
    unittest.main()
