"""Developer B integration surface: shared contracts present, versioned, loadable."""
import unittest

from validation import CONTRACTS, load_schema, schema_version

IMPLEMENTED = [
    "tenant_context", "tool_capability", "security_event", "policy_decision",
    "runtime_decision", "policy", "compiled_policy", "cache_invalidation_event",
    "risk_profile", "learning_event", "evidence", "finding",
]
# Owned by Developer B; documented seams, not yet defined here.
PENDING_DEV_B = ["approval_request", "approval_decision", "job_envelope"]


class TestIntegrationSurface(unittest.TestCase):
    def test_all_implemented_contracts_v1_and_loadable(self):
        for name in IMPLEMENTED:
            self.assertIn(name, CONTRACTS, name)
            self.assertEqual(schema_version(name), "1.0.0", name)
            self.assertIn("$id", load_schema(name), name)

    def test_pending_contracts_are_documented_not_silently_missing(self):
        # These are intentionally not implemented on the Developer A side.
        for name in PENDING_DEV_B:
            self.assertNotIn(name, CONTRACTS, f"{name} should be Developer B-owned")


if __name__ == "__main__":
    unittest.main()
