"""AgentGuard-vs-AgentGuard: all critical defenses must hold (release gate)."""
import unittest

from red_team_twin import TwinHarness


class TestAgentGuardVsAgentGuard(unittest.TestCase):
    def test_all_defenses_hold(self):
        results = TwinHarness().run_all()
        failed = [(r.scenario, r.detail) for r in results if not r.defended]
        self.assertEqual(failed, [], f"defenses failed: {failed}")
        self.assertGreaterEqual(len(results), 12)  # coverage floor


if __name__ == "__main__":
    unittest.main()
