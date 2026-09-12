"""Red-team controls: RoE/safety budget, kill switch, sandbox, planner, 50X, campaign."""
import unittest

from adaptive_attack import AdaptiveAttackEngine
from planner import AttackCandidate, AttackPlanner
from execution.safety_budget import BudgetExceeded, RulesOfEngagement, SafetyBudget
from execution.kill_switch import KillSwitch
from execution.sandbox import SandboxExecutor, SandboxPolicy
from jobs.red_team import RedTeamCampaign
from enums import RedTeamReason


def roe(**kw):
    d = dict(campaign_id="c1", authorized_targets=frozenset({"app.test"}),
             environment="test", kill_switch_owner="me",
             request_budget=1000, mutation_budget=5000, max_concurrency=4)
    d.update(kw)
    return RulesOfEngagement(**d)


class TestSafetyBudget(unittest.TestCase):
    def test_unauthorized_target(self):
        sb = SafetyBudget(roe())
        with self.assertRaises(BudgetExceeded) as ctx:
            sb.check_target("evil.example.com")
        self.assertEqual(ctx.exception.reason, RedTeamReason.ROE_TARGET_UNAUTHORIZED)

    def test_window_closed(self):
        t = [100.0]
        sb = SafetyBudget(roe(window_start=200.0), clock=lambda: t[0])
        with self.assertRaises(BudgetExceeded) as ctx:
            sb.check_target("app.test")
        self.assertEqual(ctx.exception.reason, RedTeamReason.ROE_WINDOW_CLOSED)

    def test_request_and_mutation_budget(self):
        sb = SafetyBudget(roe(request_budget=2, mutation_budget=1))
        sb.consume_request(); sb.consume_request()
        with self.assertRaises(BudgetExceeded):
            sb.consume_request()
        sb.consume_mutation()
        with self.assertRaises(BudgetExceeded):
            sb.consume_mutation()

    def test_destructive_blocked_by_default(self):
        with self.assertRaises(BudgetExceeded) as ctx:
            SafetyBudget(roe()).authorize_destructive()
        self.assertEqual(ctx.exception.reason, RedTeamReason.DESTRUCTIVE_ACTION_BLOCKED)
        SafetyBudget(roe(destructive_permitted=True)).authorize_destructive()  # ok


class TestKillSwitch(unittest.TestCase):
    def test_scopes_and_precedence(self):
        ks = KillSwitch()
        self.assertFalse(ks.is_tripped(campaign_id="c1", tenant_id="A"))
        ks.trip(actor="op", campaign_id="c1")
        self.assertTrue(ks.is_tripped(campaign_id="c1"))
        self.assertFalse(ks.is_tripped(campaign_id="c2"))
        ks.trip(actor="op", tenant_id="A")
        self.assertTrue(ks.is_tripped(campaign_id="c2", tenant_id="A"))
        ks.trip(actor="op", global_=True)
        self.assertTrue(ks.is_tripped(campaign_id="cX", tenant_id="Z"))
        self.assertTrue(any(a["op"] == "trip" for a in ks.audit_log))

    def test_recover_is_audited(self):
        ks = KillSwitch()
        ks.trip(actor="op", campaign_id="c1")
        ks.recover(actor="op", campaign_id="c1")
        self.assertFalse(ks.is_tripped(campaign_id="c1"))
        self.assertTrue(any(a["op"] == "recover" for a in ks.audit_log))


class TestSandbox(unittest.TestCase):
    def test_refusals(self):
        ex = SandboxExecutor()
        self.assertFalse(ex.execute({"destructive": True}, SandboxPolicy()).ran)
        self.assertFalse(ex.execute({"network": True}, SandboxPolicy()).ran)
        self.assertFalse(ex.execute({"capability": "x"},
                                    SandboxPolicy(allowed_capabilities=frozenset({"y"}))).ran)
        self.assertTrue(ex.execute({"capability": "y"},
                                   SandboxPolicy(allowed_capabilities=frozenset({"y"}))).ran)


class TestPlanner(unittest.TestCase):
    def test_authorized_plan_deterministic(self):
        p = AttackPlanner()
        plan1 = p.plan(target="app.test", safety_budget=SafetyBudget(roe()), seed=7)
        plan2 = p.plan(target="app.test", safety_budget=SafetyBudget(roe()), seed=7)
        self.assertEqual([s.technique for s in plan1.steps], [s.technique for s in plan2.steps])
        for s in plan1.steps:
            self.assertFalse(s.destructive)
            self.assertTrue(s.precondition and s.expected_evidence)

    def test_unauthorized_target_raises(self):
        with self.assertRaises(BudgetExceeded):
            AttackPlanner().plan(target="evil.test", safety_budget=SafetyBudget(roe()))


class Test50X(unittest.TestCase):
    def _seed_candidate(self):
        return AttackCandidate(candidate_id="c1-s0", technique="prompt_injection",
                               dimensions={}, payload="[prompt_injection]", capability="mcp.invoke")

    def test_variants_are_diverse_not_repeats(self):
        variants = AdaptiveAttackEngine().expand(
            self._seed_candidate(), factor=8, safety_budget=SafetyBudget(roe()), seed=3)
        payloads = [v.payload for v in variants]
        self.assertLessEqual(len(variants), 8)
        self.assertEqual(len(set(payloads)), len(payloads))  # distinct, not 50x same

    def test_stops_on_kill_switch(self):
        ks = KillSwitch(); ks.trip(actor="op", campaign_id="c1")
        variants = AdaptiveAttackEngine().expand(
            self._seed_candidate(), factor=8, safety_budget=SafetyBudget(roe()),
            kill_switch=ks, seed=3)
        self.assertEqual(variants, [])

    def test_bounded_by_mutation_budget(self):
        variants = AdaptiveAttackEngine().expand(
            self._seed_candidate(), factor=50,
            safety_budget=SafetyBudget(roe(mutation_budget=3)), seed=3)
        self.assertLessEqual(len(variants), 3)


class TestCampaign(unittest.TestCase):
    def test_normal_run_executes_non_destructive(self):
        r = RedTeamCampaign().run(target="app.test", safety_budget=SafetyBudget(roe()),
                                  kill_switch=KillSwitch(), tenant_id="A", factor=3)
        self.assertGreater(r.executed, 0)
        self.assertFalse(r.killed)

    def test_kill_switch_stops_campaign(self):
        ks = KillSwitch(); ks.trip(actor="op", global_=True)
        r = RedTeamCampaign().run(target="app.test", safety_budget=SafetyBudget(roe()),
                                  kill_switch=ks, tenant_id="A")
        self.assertTrue(r.killed)
        self.assertEqual(r.executed, 0)

    def test_unauthorized_campaign(self):
        r = RedTeamCampaign().run(target="evil.test", safety_budget=SafetyBudget(roe()),
                                  kill_switch=KillSwitch())
        self.assertTrue(r.unauthorized)


if __name__ == "__main__":
    unittest.main()
