"""AEGIS memory scope/provenance/poisoning + Vulnerability DNA + risk profiles."""
import unittest

from memory.episodic import EpisodicMemory
from memory.semantic import SemanticMemory
from memory.strategic import StrategicMemory
from memory.base import Provenance
from risk_profiles import RiskProfilePublisher
from validation import is_valid
import vulnerability_dna as vdna


class TestMemory(unittest.TestCase):
    def test_tenant_isolation_and_global(self):
        m = EpisodicMemory()
        m.record_attempt(tenant_id="A", technique="t", outcome="blocked", evidence_backed=True)
        m.add(key="g", content={}, confidence=0.9, provenance=Provenance("x"), verified=True)  # global
        self.assertEqual(len(m.query("A", key="t")), 1)
        self.assertEqual(len(m.query("B", key="t")), 0)  # cross-tenant isolation
        self.assertEqual(len(m.query("B", key="g")), 1)  # global visible to all

    def test_versioning(self):
        m = EpisodicMemory()
        m.record_attempt(tenant_id="A", technique="t", outcome="v1", evidence_backed=True)
        m.record_attempt(tenant_id="A", technique="t", outcome="v2", evidence_backed=True)
        recs = m.query("A", key="t")
        self.assertEqual(recs[0].version, 2)

    def test_poisoning_quarantine_then_promote(self):
        s = SemanticMemory()
        rec = s.ingest_external(key="cve-1", content={"x": 1}, source="blog", trust=0.9)
        self.assertEqual(len(s.established(None)), 0)      # unverified -> not established
        self.assertEqual(len(s.quarantined(None)), 1)
        s.promote(rec.record_id, verifier="analyst")
        self.assertEqual(len(s.established(None)), 1)

    def test_low_trust_excluded(self):
        s = SemanticMemory()
        s.ingest_external(key="k", content={}, source="untrusted", trust=0.2)
        self.assertEqual(len(s.established(None)), 0)

    def test_strategic_best_for(self):
        st = StrategicMemory()
        st.record_effectiveness(architecture="mcp", technique="a", score=0.9)
        st.record_effectiveness(architecture="mcp", technique="b", score=0.3)
        best = st.best_for("mcp")
        self.assertEqual(best[0].content["technique"], "a")


class TestVulnerabilityDNA(unittest.TestCase):
    def _finding(self, cap="database.read"):
        return {"root_cause": "missing_scope_check", "affected_architecture": "mcp",
                "model_family": "x", "agent_type": "svc", "tool_capability": cap,
                "preconditions": ["prod"], "successful_mutations": ["union select"]}

    def test_fingerprint_stable_and_similarity(self):
        a = vdna.from_finding(self._finding())
        b = vdna.from_finding(self._finding())
        self.assertEqual(a.fingerprint(), b.fingerprint())
        self.assertEqual(vdna.similarity(a, b), 1.0)
        c = vdna.from_finding(self._finding(cap="filesystem.write"))
        self.assertLess(vdna.similarity(a, c), 1.0)
        self.assertIn("root_cause", a.explainable_features())


class TestRiskProfiles(unittest.TestCase):
    def test_build_valid_and_reject_invalid(self):
        pub = RiskProfilePublisher()
        p = pub.build_profile(subject_type="tool", subject_id="t", tenant_id="A",
                              environment="production", risk_score=0.8, confidence=0.6)
        self.assertTrue(is_valid(p, "risk_profile"))
        with self.assertRaises(ValueError):
            pub.build_profile(subject_type="tool", subject_id="t", tenant_id="A",
                              environment="production", risk_score=5.0, confidence=0.6)  # out of range


if __name__ == "__main__":
    unittest.main()
