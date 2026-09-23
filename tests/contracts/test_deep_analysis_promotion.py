"""DeepAnalysisJob wires the governed promotion policy for confirmed findings."""
import unittest

from corpus_promotion import CorpusPromotionPolicy
from jobs.deep_analysis import DeepAnalysisJob
from memory.episodic import EpisodicMemory
from repository import GraphRepository
from risk_profiles import RiskProfilePublisher


def job(policy=None):
    return DeepAnalysisJob(episodic=EpisodicMemory(), graph_repo=GraphRepository(),
                           risk_publisher=RiskProfilePublisher(sink=lambda p: None),
                           corpus_policy=policy)


def finding(evidence_level, **kw):
    base = {"tenant_id": "A", "root_cause": "canary disclosure",
            "evidence_pattern": "sha256:abc", "successful_mutations": ["roleplay"],
            "tool_capability": "mcp.invoke", "evidence_level": evidence_level,
            "evidence_backed": evidence_level == "target_canary",
            "regression_fingerprint": "sha256:rf"}
    base.update(kw)
    return base


class TestDeepAnalysisPromotion(unittest.TestCase):
    def test_without_policy_behaviour_is_unchanged(self):
        result = job().analyze_finding(finding("target_canary"))
        self.assertIn("dna_fingerprint", result)
        self.assertNotIn("promoted", result)

    def test_observed_finding_is_promoted_into_corpus_and_dna(self):
        policy = CorpusPromotionPolicy()
        result = job(policy).analyze_finding(finding("target_canary"))
        self.assertTrue(result["promoted"])
        self.assertEqual(len(policy.corpus.confirmed()), 1)
        self.assertEqual(len(policy.dna_index.known()), 1)

    def test_heuristic_finding_is_quarantined_not_indexed(self):
        policy = CorpusPromotionPolicy()
        result = job(policy).analyze_finding(finding("response_heuristic"))
        self.assertFalse(result["promoted"])
        self.assertEqual(policy.corpus.confirmed(), [])
        self.assertEqual(policy.dna_index.known(), [])
        # DNA fingerprint is still computed for reporting, just not indexed.
        self.assertTrue(result["dna_fingerprint"].startswith("dna:"))


if __name__ == "__main__":
    unittest.main()
