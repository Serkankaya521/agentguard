"""Corpus/DNA promotion policy: observed evidence promotes, heuristics quarantine."""
import unittest

from corpus import AdversarialCorpus
from corpus_promotion import (CorpusPromotionPolicy, VulnerabilityDNAIndex,
                              OBSERVED_EVIDENCE_LEVELS)
from vulnerability_dna import from_finding


def finding(root_cause="canary disclosure", muts=("roleplay", "encode")):
    return {"root_cause": root_cause, "evidence_pattern": "sha256:abc",
            "successful_mutations": list(muts), "tool_capability": "mcp.invoke"}


def candidate(evidence_level, *, prompt="p", muts=("roleplay",), with_finding=True):
    return {"content": {"prompt": prompt, "mutations": list(muts)},
            "evidence_level": evidence_level,
            "finding": finding(muts=muts) if with_finding else None}


class TestPromotionPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = CorpusPromotionPolicy()

    def test_target_canary_is_promoted_and_dna_indexed(self):
        outcome = self.policy.ingest_candidate(**candidate("target_canary"))
        self.assertTrue(outcome.promoted)
        self.assertTrue(outcome.dna_fingerprint.startswith("dna:"))
        self.assertEqual(len(self.policy.corpus.confirmed()), 1)
        self.assertIn(outcome.dna_fingerprint, self.policy.dna_index.known())

    def test_heuristic_is_quarantined_never_promoted(self):
        for level in ("response_heuristic", "heuristic", "model_claim", "", "unknown"):
            policy = CorpusPromotionPolicy()
            outcome = policy.ingest_candidate(**candidate(level))
            self.assertFalse(outcome.promoted, level)
            self.assertEqual(policy.corpus.confirmed(), [])
            self.assertEqual(policy.dna_index.known(), [])
            self.assertEqual(len(policy.corpus.candidates()), 1)

    def test_high_fitness_without_observed_evidence_does_not_promote(self):
        # A caller cannot smuggle a promotion via a heuristic level, even "high".
        cand = candidate("response_heuristic")
        cand["content"]["fitness"] = 0.99
        self.assertFalse(self.policy.ingest_candidate(**cand).promoted)

    def test_all_observed_levels_promote(self):
        for level in OBSERVED_EVIDENCE_LEVELS:
            policy = CorpusPromotionPolicy()
            self.assertTrue(policy.ingest_candidate(**candidate(level)).promoted, level)

    def test_ingest_campaign_splits_promoted_and_quarantined(self):
        result = self.policy.ingest_campaign([
            candidate("target_canary", prompt="a"),
            candidate("response_heuristic", prompt="b"),
            candidate("response_heuristic", prompt="c"),
        ])
        self.assertEqual(len(result.promoted), 1)
        self.assertEqual(len(result.quarantined), 2)
        self.assertEqual(len(result.dna_fingerprints), 1)

    def test_dedup_same_content(self):
        c = candidate("target_canary", prompt="same")
        self.policy.ingest_candidate(**c)
        self.policy.ingest_candidate(**c)
        self.assertEqual(len(self.policy.corpus.confirmed()), 1)

    def test_promotion_without_finding_still_promotes_corpus_no_dna(self):
        outcome = self.policy.ingest_candidate(
            content={"prompt": "x"}, evidence_level="sandbox_observation", finding=None)
        self.assertTrue(outcome.promoted)
        self.assertEqual(outcome.dna_fingerprint, "")
        self.assertEqual(self.policy.dna_index.known(), [])


class TestDNAIndexPrioritisation(unittest.TestCase):
    def test_similar_finding_is_matched_but_not_confirmed(self):
        policy = CorpusPromotionPolicy()
        policy.ingest_candidate(**candidate("target_canary", muts=("roleplay", "encode")))
        # A new, still-heuristic candidate that looks similar is only prioritised.
        matches = policy.prioritized_matches(finding(muts=("roleplay", "encode")), threshold=0.5)
        self.assertTrue(matches)
        self.assertGreaterEqual(matches[0][1], 0.5)
        # Being similar did not promote or confirm it.
        self.assertEqual(len(policy.corpus.confirmed()), 1)

    def test_dissimilar_finding_is_not_matched(self):
        index = VulnerabilityDNAIndex(match_threshold=0.5)
        index.register(from_finding(finding(root_cause="A", muts=("x",))))
        self.assertEqual(index.matches(from_finding(finding(root_cause="B", muts=("y",)))), [])


if __name__ == "__main__":
    unittest.main()
