"""Live red-team targets: RoE authorisation, secret scoping, kill switch, budget."""
import asyncio
import json
import unittest
from dataclasses import dataclass

from enums import RedTeamReason
from execution.kill_switch import KillSwitch
from execution.live_target import (HALTED, GuardedEvaluator, RoEConfig, ScopedSecretResolver,
                                   SecretNotAuthorized, TargetNotAuthorized, authorize_campaign,
                                   build_roe, finalize, target_origin)
from execution.safety_budget import SafetyBudget

TENANT = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
ROE = RoEConfig.from_json(json.dumps({"tenants": {
    TENANT: {"targets": ["https://agent.acme.example"], "secrets": ["AG_RT_ACME_KEY", "AG_RT_ACME_CANARY"]},
    "*": {"targets": ["http://127.0.0.1:8000"]},
}}))


def campaign(**kw):
    row = {"id": "c-1", "tenant_id": TENANT, "environment_id": "env", "request_budget": 10,
           "mutation_budget": 10, "max_concurrency": 1, "secret_ref": "env://AG_RT_ACME_KEY",
           "canary_secret_ref": "env://AG_RT_ACME_CANARY",
           "target_config": {"api_base": "https://agent.acme.example/v1", "model": "gpt-x"}}
    row.update(kw)
    return row


class CountingTarget:
    def __init__(self):
        self.prompts = []

    async def __call__(self, prompt):
        self.prompts.append(prompt)
        return "ok"


def guarded(row=None, kill=None, target="https://agent.acme.example:443"):
    row = row or campaign()
    budget = SafetyBudget(build_roe(row, ROE.for_tenant(row["tenant_id"])))
    inner = CountingTarget()
    return inner, GuardedEvaluator(inner, target=target, budget=budget,
                                   kill_switch=kill or KillSwitch(), tenant_id=row["tenant_id"])


def run_all(guard, n):
    async def go():
        return await asyncio.gather(*(guard(f"p{i}") for i in range(n)))
    return asyncio.run(go())


class TestTargetOrigin(unittest.TestCase):
    def test_normalises_scheme_host_and_default_port(self):
        self.assertEqual(target_origin("HTTPS://Agent.Acme.Example/v1/chat"), "https://agent.acme.example:443")
        self.assertEqual(target_origin("http://[::1]:9000/x"), "http://[::1]:9000")

    def test_rejects_credentials_and_non_http(self):
        for bad in ("https://user:pw@agent.acme.example", "ftp://agent.acme.example", "agent.acme.example", ""):
            with self.assertRaises(ValueError, msg=bad):
                target_origin(bad)


class TestAuthorizeCampaign(unittest.TestCase):
    def test_authorised_tenant_target_and_secrets_pass(self):
        authorize_campaign(campaign(), ROE.for_tenant(TENANT), live=True)

    def test_lookalike_and_prefix_hosts_are_not_authorised(self):
        for base in ("https://agent.acme.example.attacker.example", "http://127.0.0.1.nip.io:8000",
                     "http://localhost.attacker.example:8000", "https://agent.acme.example:8443"):
            row = campaign(target_config={"api_base": base, "model": "gpt-x"})
            with self.assertRaises(TargetNotAuthorized, msg=base):
                authorize_campaign(row, ROE.for_tenant(TENANT), live=True)

    def test_tenant_without_entry_is_denied_by_default(self):
        row = campaign(tenant_id=OTHER, secret_ref=None, canary_secret_ref=None)
        with self.assertRaises(TargetNotAuthorized):
            authorize_campaign(row, ROE.for_tenant(OTHER), live=True)
        # the wildcard loopback lab target is available to every tenant
        row["target_config"] = {"api_base": "http://127.0.0.1:8000/v1", "model": "gpt-x"}
        authorize_campaign(row, ROE.for_tenant(OTHER), live=True)

    def test_platform_or_foreign_secrets_are_refused(self):
        for ref in ("env://CONTROL_DATABASE_URL", "env://AG_RT_OTHER_KEY", "vault://x"):
            with self.assertRaises(SecretNotAuthorized, msg=ref):
                authorize_campaign(campaign(secret_ref=ref), ROE.for_tenant(TENANT), live=True)
        # another tenant cannot borrow ACME's key
        row = campaign(tenant_id=OTHER, canary_secret_ref=None,
                       target_config={"api_base": "http://127.0.0.1:8000", "model": "gpt-x"})
        with self.assertRaises(SecretNotAuthorized):
            authorize_campaign(row, ROE.for_tenant(OTHER), live=True)

    def test_offline_mock_campaign_needs_no_target_authorisation(self):
        row = campaign(target_config={"api_base": "", "model": "mock-agent"})
        authorize_campaign(row, ROE.for_tenant(TENANT), live=False)


class TestScopedSecretResolver(unittest.TestCase):
    def test_only_roe_assigned_names_are_resolved(self):
        seen = []
        resolver = ScopedSecretResolver(ROE, lambda ref: seen.append(ref) or "value")
        self.assertEqual(resolver("env://AG_RT_ACME_KEY"), "value")
        self.assertIsNone(resolver(None))
        with self.assertRaises(SecretNotAuthorized):
            resolver("env://CONTROL_DATABASE_URL")
        self.assertEqual(seen, ["env://AG_RT_ACME_KEY"])  # platform secret never read

    def test_empty_config_denies_everything(self):
        with self.assertRaises(SecretNotAuthorized):
            ScopedSecretResolver(RoEConfig.from_json(None), lambda ref: "v")("env://AG_RT_ACME_KEY")


class TestGuardedEvaluator(unittest.TestCase):
    def test_budget_caps_live_traffic(self):
        inner, guard = guarded(campaign(request_budget=3, mutation_budget=3))
        out = run_all(guard, 8)
        self.assertEqual(len(inner.prompts), 3)
        self.assertEqual(out.count(HALTED), 5)
        self.assertEqual(guard.halt_reason, RedTeamReason.SAFETY_BUDGET_EXHAUSTED)

    def test_kill_switch_stops_in_flight_campaign(self):
        kill = KillSwitch()
        inner, guard = guarded(kill=kill)

        async def go():
            first = await guard("a")
            kill.trip(actor="operator", campaign_id="c-1")
            return first, await guard("b"), await guard("c")
        self.assertEqual(asyncio.run(go()), ("ok", HALTED, HALTED))
        self.assertEqual(inner.prompts, ["a"])
        self.assertEqual(guard.halt_reason, RedTeamReason.KILL_SWITCH_TRIPPED)

    def test_tenant_and_global_kill_scopes_apply(self):
        for scope in ({"tenant_id": TENANT}, {"global_": True}):
            kill = KillSwitch()
            kill.trip(actor="operator", **scope)
            inner, guard = guarded(kill=kill)
            self.assertEqual(run_all(guard, 2), [HALTED, HALTED])
            self.assertEqual(inner.prompts, [])

    def test_unauthorised_target_sends_nothing(self):
        inner, guard = guarded(target="https://evil.example:443")
        self.assertEqual(run_all(guard, 3), [HALTED] * 3)
        self.assertEqual(inner.prompts, [])
        self.assertEqual(guard.halt_reason, RedTeamReason.ROE_TARGET_UNAUTHORIZED)

    def test_concurrency_is_bounded_by_roe(self):
        active = peak = 0

        async def slow(prompt):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.001)
            active -= 1
            return "ok"
        row = campaign(max_concurrency=2)
        budget = SafetyBudget(build_roe(row, ROE.for_tenant(TENANT)))
        guard = GuardedEvaluator(slow, target="https://agent.acme.example:443", budget=budget,
                                 kill_switch=KillSwitch(), tenant_id=TENANT)
        self.assertEqual(run_all(guard, 6), ["ok"] * 6)
        self.assertEqual(peak, 2)


@dataclass(frozen=True)
class _Candidate:
    response_sample: str
    fitness_score: float


@dataclass(frozen=True)
class _Summary:
    candidates: tuple
    candidates_evaluated: int
    findings: int
    best_score: float
    halt_reason: object = None


class TestFinalize(unittest.TestCase):
    def test_reports_only_sent_requests_and_the_halt_reason(self):
        _, guard = guarded(campaign(request_budget=2, mutation_budget=2))
        run_all(guard, 4)
        summary = _Summary(candidates=(_Candidate("ok", 0.9), _Candidate("ok", 0.2),
                                       _Candidate(HALTED, 0.4), _Candidate(HALTED, 0.4)),
                           candidates_evaluated=4, findings=1, best_score=0.9)
        out = finalize(summary, guard)
        self.assertEqual(len(out.candidates), 2)
        self.assertEqual(out.candidates_evaluated, 2)
        self.assertEqual((out.findings, out.best_score), (1, 0.9))
        self.assertEqual(out.halt_reason, "SAFETY_BUDGET_EXHAUSTED")


if __name__ == "__main__":
    unittest.main()
