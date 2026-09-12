"""Evidence: integrity, model-claim-insufficiency, blocked!=executed, chain."""
import unittest

import integrity
from capture import EvidenceCapture, EvidenceSource, EvidenceValidator
from validation import is_valid

KEY = "ev-key"


class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.cap = EvidenceCapture(KEY)
        self.val = EvidenceValidator(KEY)

    def test_observed_evidence_is_backed_and_schema_valid(self):
        rec = self.cap.capture(tenant_id="A", event_id="e1", action_state="executed",
                               sources=[EvidenceSource("resource_mutation", "sha256:abc")])
        self.assertTrue(is_valid(rec.to_dict(), "evidence"))
        res = self.val.validate(rec)
        self.assertTrue(res.integrity_ok and res.evidence_backed and res.supports_success)

    def test_model_claim_alone_not_sufficient(self):
        rec = self.cap.capture(tenant_id="A", event_id="e1", action_state="executed",
                               sources=[EvidenceSource("model_claim", "ref")])
        res = self.val.validate(rec)
        self.assertFalse(res.evidence_backed)
        self.assertIn("model_claim_only_not_sufficient", res.reasons)

    def test_blocked_does_not_support_success(self):
        rec = self.cap.capture(tenant_id="A", event_id="e1", action_state="blocked",
                               sources=[EvidenceSource("policy_trace", "ref")])
        self.assertFalse(self.val.validate(rec).supports_success)

    def test_tamper_detected(self):
        rec = self.cap.capture(tenant_id="A", event_id="e1", action_state="executed",
                               sources=[EvidenceSource("resource_mutation", "sha256:abc")])
        data = rec.to_dict()
        self.assertTrue(integrity.verify(data, KEY)[0])
        data["sources"][0]["ref"] = "sha256:TAMPERED"
        self.assertFalse(integrity.verify(data, KEY)[0])

    def test_chain_integrity(self):
        r1 = self.cap.capture(tenant_id="A", event_id="e1", action_state="executed",
                              sources=[EvidenceSource("hash", "h1")])
        r2 = self.cap.capture(tenant_id="A", event_id="e2", action_state="executed",
                              sources=[EvidenceSource("hash", "h2")], prev_hash=r1.integrity_hash)
        ok, _ = integrity.verify_chain([r1.to_dict(), r2.to_dict()], KEY)
        self.assertTrue(ok)
        broken = r2.to_dict(); broken["prev_hash"] = "sha256:WRONG"
        # broken prev_hash also breaks integrity_hash -> chain invalid
        self.assertFalse(integrity.verify_chain([r1.to_dict(), broken], KEY)[0])


if __name__ == "__main__":
    unittest.main()
