"""Sprint A7 — P2 gaps: threat research, templates, versioning, corpus, eval, chains."""
import unittest

from threat_research import ThreatItem, ThreatResearchIngestion
from attack_templates import AttackTemplateRegistry
from versioning import ArtifactVersionRegistry
from corpus import AdversarialCorpus
from evaluation import CanaryEvaluator, GateThresholds, ShadowEvaluator, evaluate
from chain_explorer import ChainExplorer
from planner import AttackCandidate
from governance import Proposal
from memory.semantic import SemanticMemory
from execution.safety_budget import RulesOfEngagement, SafetyBudget
from execution.kill_switch import KillSwitch


def _roe():
    return RulesOfEngagement(campaign_id="c1", authorized_targets=frozenset({"app.test"}),
                             environment="test", kill_switch_owner="op", mutation_budget=100)


class TestThreatResearch(unittest.TestCase):
    def _setup(self):
        sem = SemanticMemory()
        ing = ThreatResearchIngestion(sem)
        item = ThreatItem("cve-2026-1", "nvd", "cve", {"summary": "x"})
        rec = ing.ingest(item)
        return sem, ing, item, rec

    def test_ingest_quarantines(self):
        sem, ing, item, rec = self._setup()
        self.assertEqual(len(sem.established(None)), 0)   # untrusted until promoted
        self.assertEqual(len(sem.quarantined(None)), 1)

    def test_promotion_requires_all_gates(self):
        sem, ing, item, rec = self._setup()
        # missing cross-validation + failing sandbox
        d = ing.promote(item, rec.record_id, corroborating_sources=1,
                        sandbox_reproduce=lambda i: False, verifier="")
        self.assertFalse(d.promoted)
        self.assertIn("insufficient_cross_validation", d.reasons)
        self.assertIn("sandbox_reproduction_failed", d.reasons)
        self.assertIn("human_verifier_required", d.reasons)
        # all gates pass
        d2 = ing.promote(item, rec.record_id, corroborating_sources=2,
                         sandbox_reproduce=lambda i: True, verifier="analyst")
        self.assertTrue(d2.promoted)
        self.assertEqual(len(sem.established(None)), 1)

    def test_low_trust_source_blocked(self):
        sem = SemanticMemory(); ing = ThreatResearchIngestion(sem)
        item = ThreatItem("b1", "randomblog", "blog", {"x": 1})
        rec = ing.ingest(item)
        d = ing.promote(item, rec.record_id, corroborating_sources=5,
                        sandbox_reproduce=lambda i: True, verifier="a")
        self.assertFalse(d.promoted)
        self.assertIn("source_trust_below_threshold", d.reasons)


class TestAttackTemplates(unittest.TestCase):
    def test_activation_requires_governed_proposal(self):
        reg = AttackTemplateRegistry()
        reg.add_draft(template_id="t1", name="Injection", technique="prompt_injection",
                      version="1", content={}, provenance="aegis")
        reg.propose("t1")
        with self.assertRaises(ValueError):  # not a PRODUCTION proposal
            reg.activate("t1", approved_proposal=Proposal("p", "attack_template", {}, stage="CANARY"))
        prod = Proposal("p", "attack_template", {}, stage="PRODUCTION")
        t = reg.activate("t1", approved_proposal=prod)
        self.assertEqual(t.state, "active")
        self.assertEqual(len(reg.active_templates()), 1)

    def test_wrong_kind_rejected(self):
        reg = AttackTemplateRegistry()
        reg.add_draft(template_id="t1", name="x", technique="y", version="1",
                      content={}, provenance="a")
        reg.propose("t1")
        with self.assertRaises(ValueError):
            reg.activate("t1", approved_proposal=Proposal("p", "detector", {}, stage="PRODUCTION"))


class TestVersioning(unittest.TestCase):
    def test_immutable_active_rollback(self):
        reg = ArtifactVersionRegistry()
        reg.publish(kind="detector", name="sqli", version="1.0.0", content={"a": 1}, provenance="p")
        with self.assertRaises(ValueError):
            reg.publish(kind="detector", name="sqli", version="1.0.0", content={"a": 2}, provenance="p")
        reg.publish(kind="detector", name="sqli", version="1.1.0", content={"a": 2}, provenance="p")
        self.assertEqual(reg.active("detector", "sqli").version, "1.1.0")
        self.assertEqual(reg.rollback("detector", "sqli").version, "1.0.0")
        self.assertEqual(len(reg.list_versions("detector", "sqli")), 2)


class TestCorpus(unittest.TestCase):
    def test_dedup_and_evidence_gated_promotion(self):
        c = AdversarialCorpus()
        e1 = c.add(content={"p": "x"}, provenance="fuzzer")
        e2 = c.add(content={"p": "x"}, provenance="fuzzer")  # duplicate
        self.assertEqual(e1.fingerprint, e2.fingerprint)
        self.assertEqual(len(c.candidates()), 1)
        with self.assertRaises(ValueError):
            c.promote_to_regression(e1.fingerprint, evidence_backed=False)
        c.promote_to_regression(e1.fingerprint, evidence_backed=True)
        self.assertEqual(len(c.confirmed()), 1)


class TestEvaluation(unittest.TestCase):
    def _corpus(self):
        # 8 malicious, 2 benign
        return ([{"sample": {"m": True}, "malicious": True} for _ in range(8)]
                + [{"sample": {"m": False}, "malicious": False} for _ in range(2)])

    def test_perfect_detector_passes(self):
        res = ShadowEvaluator().run(lambda s: s["m"], self._corpus())
        self.assertTrue(res.passed)
        self.assertEqual(res.metrics.detection_rate, 1.0)
        self.assertEqual(res.metrics.fpr, 0.0)

    def test_noisy_detector_fails_on_fpr(self):
        res = ShadowEvaluator().run(lambda s: True, self._corpus())  # flags everything
        self.assertFalse(res.passed)
        self.assertIn("fpr_too_high", res.reasons)

    def test_canary_bounded_sample(self):
        res = CanaryEvaluator().run(lambda s: s["m"], self._corpus(), sample_fraction=0.5, seed=1)
        self.assertLessEqual(res.metrics.total, 5)


class TestChainExplorer(unittest.TestCase):
    def _seed(self):
        return AttackCandidate(candidate_id="s0", technique="prompt_injection",
                               dimensions={}, payload="[prompt_injection]", capability="mcp.invoke")

    def test_bounded_deterministic_chains(self):
        args = dict(seeds=[self._seed()], max_depth=4, max_chains=3,
                    safety_budget=SafetyBudget(_roe()), seed=5)
        c1 = ChainExplorer().explore(**args)
        c2 = ChainExplorer().explore(**{**args, "safety_budget": SafetyBudget(_roe())})
        self.assertLessEqual(len(c1), 3)
        self.assertTrue(all(ch.depth <= 4 for ch in c1))
        self.assertTrue(all(not st.destructive for ch in c1 for st in ch.steps))
        self.assertEqual([ch.techniques for ch in c1], [ch.techniques for ch in c2])  # deterministic
        self.assertGreaterEqual(c1[0].depth, 2)  # multi-turn chain built

    def test_kill_switch_stops_extension(self):
        ks = KillSwitch(); ks.trip(actor="op", global_=True)
        chains = ChainExplorer().explore(seeds=[self._seed()], max_depth=5, max_chains=3,
                                         safety_budget=SafetyBudget(_roe()), kill_switch=ks)
        self.assertTrue(all(ch.depth == 1 for ch in chains))  # no extension past first step


if __name__ == "__main__":
    unittest.main()
