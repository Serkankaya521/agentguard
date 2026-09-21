"""Side-effect observer: observed-change evidence, no raw payload, blocked != executed."""
import unittest

from capture import EvidenceValidator
from side_effects import SideEffectObserver
from serialization import content_hash


class TestSideEffectObserver(unittest.TestCase):
    def test_mutation_with_changed_hashes_is_a_success_kind(self):
        obs = SideEffectObserver()
        obs.resource_mutation("crm.customers/42", operation="update",
                              before_hash="sha256:a", after_hash="sha256:b")
        self.assertTrue(obs.had_side_effects())
        (src,) = obs.to_evidence_sources()
        self.assertEqual(src.kind, "resource_mutation")

    def test_unchanged_update_is_not_a_change(self):
        obs = SideEffectObserver()
        obs.resource_mutation("f", operation="update", before_hash="sha256:x", after_hash="sha256:x")
        self.assertFalse(obs.had_side_effects())
        self.assertEqual(obs.to_evidence_sources()[0].kind, "tool_output")

    def test_create_and_delete_are_changes_even_without_hashes(self):
        for op in ("create", "delete"):
            obs = SideEffectObserver()
            obs.resource_mutation("r", operation=op)
            self.assertTrue(obs.had_side_effects(), op)

    def test_reads_and_output_are_observed_but_not_changes(self):
        obs = SideEffectObserver()
        obs.resource_read("crm.customers/42", result_hash="sha256:r")
        obs.tool_output("some tool text")
        self.assertFalse(obs.had_side_effects())
        self.assertEqual({s.kind for s in obs.to_evidence_sources()}, {"tool_output"})

    def test_network_and_state_are_changes(self):
        obs = SideEffectObserver()
        obs.network_event("evil.example", direction="egress", port=443, bytes_out=2048)
        obs.deterministic_state("row_exists", {"id": 42})
        self.assertTrue(obs.had_side_effects())
        self.assertEqual({s.kind for s in obs.to_evidence_sources()},
                         {"network_event", "deterministic_state"})

    def test_no_raw_payload_only_hashes(self):
        obs = SideEffectObserver()
        secret = "4111111111111111"
        obs.tool_output(secret)
        obs.deterministic_state("card", secret)
        blob = str(obs.observations) + str([s.summary for s in obs.to_evidence_sources()])
        self.assertNotIn(secret, blob)
        self.assertIn(content_hash(secret), blob)

    def test_bounded_observations(self):
        obs = SideEffectObserver(max_observations=2)
        for _ in range(5):
            obs.resource_read("r")
        self.assertEqual(len(obs.observations), 2)
        self.assertEqual(obs.dropped, 3)


class TestReconciliation(unittest.TestCase):
    def test_executed_with_effects_is_consistent(self):
        obs = SideEffectObserver()
        obs.resource_mutation("r", operation="create")
        rec = obs.reconcile("executed")
        self.assertTrue(rec.consistent and rec.executed_with_effects)

    def test_blocked_with_side_effects_is_an_enforcement_bypass(self):
        obs = SideEffectObserver()
        obs.network_event("evil.example")
        rec = obs.reconcile("blocked")
        self.assertFalse(rec.consistent)
        self.assertTrue(any("enforcement_bypass" in r for r in rec.reasons))

    def test_blocked_without_effects_is_consistent(self):
        rec = SideEffectObserver().reconcile("blocked")
        self.assertTrue(rec.consistent)
        self.assertFalse(rec.executed_with_effects)

    def test_executed_without_effect_is_flagged_but_consistent(self):
        rec = SideEffectObserver().reconcile("executed")
        self.assertTrue(rec.consistent)
        self.assertIn("executed_without_observable_effect", rec.reasons)


class TestEvidenceIntegration(unittest.TestCase):
    def test_observer_sources_validate_and_support_success_only_when_executed(self):
        from capture import EvidenceCapture
        cap = EvidenceCapture("k")
        obs = SideEffectObserver()
        obs.resource_mutation("crm/1", operation="update", before_hash="sha256:a",
                              after_hash="sha256:b")
        rec = cap.capture(tenant_id="A", event_id="e1", action_state="executed",
                          sources=obs.to_evidence_sources())
        result = EvidenceValidator("k").validate(rec)
        self.assertTrue(result.integrity_ok and result.evidence_backed)
        self.assertTrue(result.supports_success)

        blocked = cap.capture(tenant_id="A", event_id="e2", action_state="blocked",
                              sources=obs.to_evidence_sources())
        self.assertFalse(EvidenceValidator("k").validate(blocked).supports_success)


if __name__ == "__main__":
    unittest.main()
