"""Evolutionary fuzzer, regression engine, and finding lifecycle."""
import unittest

from evolutionary_search import GeneticFuzzer
from regression import RegressionEngine
from finding import Finding, InvalidTransition
from enums import FindingState, RedTeamReason
from serialization import to_jsonable
from validation import is_valid


class TestFuzzer(unittest.TestCase):
    def test_bounded_and_deduped(self):
        f = GeneticFuzzer(seed=1, population_size=10, generations=3)
        pop = f.run()
        self.assertLessEqual(len(pop), 10)
        # corpus keyed by signature -> no duplicate signatures
        self.assertEqual(len(f.corpus), len({tuple(g.genes.values()) for g in f.corpus.values()}))

    def test_deterministic_reproducible(self):
        best1 = GeneticFuzzer(seed=42, population_size=10, generations=4).run()[0]
        best2 = GeneticFuzzer(seed=42, population_size=10, generations=4).run()[0]
        self.assertEqual(best1.genes, best2.genes)

    def test_lineage_and_heuristic_not_evidence(self):
        f = GeneticFuzzer(seed=2, population_size=8, generations=3)
        f.run()
        self.assertTrue(any(g.parents for g in f.corpus.values()))  # children have parents
        promoted = f.promote_candidates(threshold=0.4)
        if promoted:
            self.assertEqual(promoted[0]["note"], RedTeamReason.HEURISTIC_ONLY_NOT_EVIDENCE.value)


class TestRegression(unittest.TestCase):
    def _finding(self, state=FindingState.RESOLVED_VERIFIED, cap="database.read"):
        return {"schema_version": "1.0.0", "finding_id": "f1", "tenant_id": "A",
                "state": state.value, "root_cause": "missing_scope_check",
                "affected_architecture": "mcp", "tool_capability": cap,
                "successful_mutations": ["union select"], "preconditions": ["prod"]}

    def test_register_requires_resolved_verified(self):
        eng = RegressionEngine()
        with self.assertRaises(ValueError):
            eng.register(self._finding(state=FindingState.CONFIRMED))
        case = eng.register(self._finding(), amplified=["' or 1=1"], chain=["read->egress"])
        self.assertIn("union select", case.payloads)
        self.assertIn("' or 1=1", case.payloads)

    def test_replay_pass_and_reopen(self):
        eng = RegressionEngine()
        case = eng.register(self._finding())
        self.assertTrue(eng.replay(case, defense=lambda p: True).passed)
        r = eng.replay(case, defense=lambda p: False)
        self.assertFalse(r.passed)
        self.assertEqual(r.reason, RedTeamReason.REGRESSION_REOPENED)

    def test_match_similar_finding(self):
        eng = RegressionEngine()
        eng.register(self._finding())
        match = eng.match(self._finding(state=FindingState.CONFIRMED))  # same signature
        self.assertIsNotNone(match)
        self.assertIsNone(eng.match({"finding_id": "z", "tenant_id": "A", "state": "CONFIRMED",
                                     "root_cause": "totally_different", "tool_capability": "x"}))


class TestFindingLifecycle(unittest.TestCase):
    def test_valid_and_invalid_transitions(self):
        f = Finding(finding_id="f1", tenant_id="A", state=FindingState.SUSPECTED,
                    root_cause="rc")
        f = f.transition(FindingState.VALIDATING).transition(FindingState.CONFIRMED)
        self.assertEqual(f.state, FindingState.CONFIRMED)
        with self.assertRaises(InvalidTransition):
            f.transition(FindingState.RESOLVED_VERIFIED)  # must go via FIX_PROPOSED/RETESTING

    def test_resolved_reopen_and_schema(self):
        f = Finding(finding_id="f1", tenant_id="A", state=FindingState.RETESTING, root_cause="rc")
        f = f.transition(FindingState.RESOLVED_VERIFIED)
        f = f.transition(FindingState.REOPENED)  # recurrence -> REOPENED, not a new record
        self.assertEqual(f.state, FindingState.REOPENED)
        self.assertTrue(is_valid(to_jsonable(f), "finding"))


if __name__ == "__main__":
    unittest.main()
