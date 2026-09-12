"""Self-improvement governance: no self-deploy; production needs approval + signature."""
import unittest

from governance import GovernancePipeline, GovernanceViolation, Proposal, ProductionRegistry, STAGES
from learning import cold_requirements, warm_propose_detector, warm_propose_policy
from memory.strategic import StrategicMemory
import learning


AUTOMATED = STAGES[1:8]  # UNIT_TESTS..CANARY


def _drive_automated(gp, prop):
    for gate in AUTOMATED:
        prop = gp.pass_gate(prop, gate, passed=True)
    return prop


class TestGovernance(unittest.TestCase):
    def setUp(self):
        self.gp = GovernancePipeline(signing_key="k")
        self.prop = Proposal(proposal_id="p1", kind="detector", content={"x": 1})

    def test_happy_path_to_production_and_rollback(self):
        p = _drive_automated(self.gp, self.prop)
        p = self.gp.approve(p, approver="alice")
        p = self.gp.sign(p)
        p = self.gp.promote(p)
        self.assertEqual(p.stage, "PRODUCTION")
        reg = ProductionRegistry()
        reg.deploy(p)
        self.assertEqual(reg.active("detector").proposal_id, "p1")
        # deploy a v2, then rollback to v1
        p2 = self.gp.promote(self.gp.sign(self.gp.approve(
            _drive_automated(self.gp, Proposal("p2", "detector", {})), approver="bob")))
        reg.deploy(p2)
        self.assertEqual(reg.active("detector").proposal_id, "p2")
        self.assertEqual(reg.rollback("detector").proposal_id, "p1")

    def test_cannot_skip_gate(self):
        with self.assertRaises(GovernanceViolation):
            self.gp.pass_gate(self.prop, "SANDBOX", passed=True)  # out of order

    def test_cannot_approve_before_canary(self):
        with self.assertRaises(GovernanceViolation):
            self.gp.approve(self.prop, approver="alice")

    def test_cannot_sign_before_human_approval(self):
        p = _drive_automated(self.gp, self.prop)
        with self.assertRaises(GovernanceViolation):
            self.gp.sign(p)

    def test_cannot_promote_before_signed(self):
        p = self.gp.approve(_drive_automated(self.gp, self.prop), approver="alice")
        with self.assertRaises(GovernanceViolation):
            self.gp.promote(p)

    def test_non_human_approval_rejected(self):
        p = _drive_automated(self.gp, self.prop)
        with self.assertRaises(GovernanceViolation):
            self.gp.approve(p, approver="aegis", is_human=False)

    def test_aegis_cannot_self_deploy(self):
        with self.assertRaises(GovernanceViolation):
            self.gp.aegis_attempt_deploy(self.prop)


class TestLearningTiers(unittest.TestCase):
    def test_hot_updates_memory_only(self):
        sm = StrategicMemory()
        rec = learning.hot_update(sm, architecture="mcp", technique="t", score=0.8)
        self.assertEqual(rec.memory_type, "strategic")

    def test_warm_produces_proposals(self):
        self.assertEqual(warm_propose_detector(pattern_label="x", sample_signals=[]).kind, "detector")
        self.assertEqual(warm_propose_policy(change={}).kind, "policy")

    def test_cold_requires_human_approval(self):
        self.assertTrue(cold_requirements()["human_approval"])


if __name__ == "__main__":
    unittest.main()
