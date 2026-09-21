"""Rules of Engagement for live red-team targets (security worker, task plan 25).

Registering a target in the control plane is a tenant's *claim*; it is not proof
that the tenant may attack that endpoint. Live campaign traffic therefore needs an
operator-issued RoE entry for the tenant (``REDTEAM_ROE_FILE`` or ``REDTEAM_ROE_JSON``)::

    {"tenants": {"<tenant-id>": {
        "targets": ["https://agent.customer.example"],
        "secrets": ["AG_REDTEAM_ACME_API_KEY", "AG_REDTEAM_ACME_CANARY"]}}}

- A target is authorised by exact origin (scheme, host, port), so a look-alike host
  such as ``localhost.attacker.example`` never matches ``localhost``.
- A campaign may only resolve the secret names listed for its tenant, so ``env://``
  cannot reach platform credentials or another tenant's keys.
- Every live request passes the kill switch and the safety budget. Once either halts
  the campaign no further traffic is sent, and the result records why.

Tenants without an entry get nothing (deny by default). The ``"*"`` entry applies to
every tenant and is meant for local labs (e.g. a loopback target).
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
from dataclasses import dataclass
from typing import Awaitable, Callable, Mapping, Optional
from urllib.parse import urlsplit

from enums import RedTeamReason
from execution.safety_budget import BudgetExceeded, RulesOfEngagement, SafetyBudget

HALTED = "[CAMPAIGN_HALTED]"
_DEFAULT_PORTS = {"http": 80, "https": 443}

Evaluator = Callable[[str], Awaitable[str]]


class RoEViolation(PermissionError):
    """Raised before any target traffic; the class name becomes the run's error code."""
    reason = RedTeamReason.ROE_TARGET_UNAUTHORIZED


class TargetNotAuthorized(RoEViolation):
    reason = RedTeamReason.ROE_TARGET_UNAUTHORIZED


class SecretNotAuthorized(RoEViolation):
    reason = RedTeamReason.ROE_SECRET_UNAUTHORIZED


def target_origin(url: str) -> str:
    """Normalise a URL to ``scheme://host:port`` for exact RoE matching."""
    parts = urlsplit(str(url).strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError("target must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("target must not embed credentials")
    host = parts.hostname.rstrip(".")
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return f"{scheme}://{host}:{parts.port or _DEFAULT_PORTS[scheme]}"


def secret_name(reference: str) -> str:
    if not reference.startswith("env://"):
        raise SecretNotAuthorized("only env:// secret references are supported")
    return reference[len("env://"):]


@dataclass(frozen=True)
class TenantRoE:
    targets: frozenset[str] = frozenset()
    secrets: frozenset[str] = frozenset()


class RoEConfig:
    WILDCARD = "*"

    def __init__(self, tenants: Mapping[str, TenantRoE]) -> None:
        self._tenants = dict(tenants)

    @classmethod
    def from_json(cls, text: Optional[str]) -> "RoEConfig":
        if not text or not text.strip():
            return cls({})
        doc = json.loads(text)
        return cls({
            str(tenant_id): TenantRoE(
                targets=frozenset(target_origin(t) for t in entry.get("targets", ())),
                secrets=frozenset(str(s) for s in entry.get("secrets", ())))
            for tenant_id, entry in (doc.get("tenants") or {}).items()})

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "RoEConfig":
        path = environ.get("REDTEAM_ROE_FILE")
        if path:
            with open(path, encoding="utf-8") as fh:
                return cls.from_json(fh.read())
        return cls.from_json(environ.get("REDTEAM_ROE_JSON"))

    def for_tenant(self, tenant_id) -> TenantRoE:
        own = self._tenants.get(str(tenant_id), TenantRoE())
        shared = self._tenants.get(self.WILDCARD, TenantRoE())
        return TenantRoE(own.targets | shared.targets, own.secrets | shared.secrets)

    def assigned_secrets(self) -> frozenset[str]:
        return frozenset().union(*(t.secrets for t in self._tenants.values()))


class ScopedSecretResolver:
    """Resolves only secret names the RoE assigns to some tenant.

    Platform credentials (database DSN, object-store keys, ...) live in the same
    worker environment, so an unscoped ``env://`` lookup would hand them to any
    campaign. Per-tenant scoping is enforced again in :func:`authorize_campaign`.
    """

    def __init__(self, roe: RoEConfig, resolve: Callable[[str], Optional[str]]) -> None:
        self._roe = roe
        self._resolve = resolve

    def __call__(self, reference: Optional[str]) -> Optional[str]:
        if not reference:
            return None
        if secret_name(reference) not in self._roe.assigned_secrets():
            raise SecretNotAuthorized("secret is not assigned by the RoE")
        return self._resolve(reference)


def authorize_campaign(campaign: Mapping, tenant_roe: TenantRoE, *, live: bool) -> None:
    """Pre-flight check; raises before any request reaches the target."""
    for ref in (campaign.get("secret_ref"), campaign.get("canary_secret_ref")):
        if ref and secret_name(ref) not in tenant_roe.secrets:
            raise SecretNotAuthorized("secret is not assigned to this tenant")
    if live:
        try:
            origin = target_origin(str((campaign.get("target_config") or {}).get("api_base", "")))
        except ValueError as exc:
            raise TargetNotAuthorized(str(exc)) from None
        if origin not in tenant_roe.targets:
            raise TargetNotAuthorized("target origin is not authorised for this tenant")


def build_roe(campaign: Mapping, tenant_roe: TenantRoE) -> RulesOfEngagement:
    return RulesOfEngagement(
        campaign_id=str(campaign["id"]),
        authorized_targets=tenant_roe.targets,
        environment=str(campaign.get("environment_id", "")),
        kill_switch_owner="security-worker",
        max_concurrency=int(campaign.get("max_concurrency") or 1),
        request_budget=int(campaign["request_budget"]),
        mutation_budget=int(campaign["mutation_budget"]),
    )


class GuardedEvaluator:
    """Wraps the live target call: kill switch, RoE and budget before every request.

    It never raises into the fuzzer. After the first halt every call returns
    :data:`HALTED` without touching the target, so partial evidence is kept and the
    campaign winds down with ``halt_reason`` set.
    """

    def __init__(self, evaluate: Evaluator, *, target: Optional[str], budget: SafetyBudget,
                 kill_switch, tenant_id: str) -> None:
        self._evaluate = evaluate
        self._target = target  # None: offline/mock evaluator, no target traffic
        self._budget = budget
        self._kill = kill_switch
        self._tenant_id = tenant_id
        self._slots = asyncio.Semaphore(max(1, budget.roe.max_concurrency))
        self.sent = 0
        self.halt_reason: Optional[RedTeamReason] = None

    def _admit(self) -> Optional[RedTeamReason]:
        if self._kill.is_tripped(campaign_id=self._budget.roe.campaign_id,
                                 tenant_id=self._tenant_id):
            return RedTeamReason.KILL_SWITCH_TRIPPED
        try:
            if self._target is not None:
                self._budget.check_target(self._target)
            self._budget.consume_request()
            self._budget.consume_mutation()
        except BudgetExceeded as exc:
            return exc.reason
        return None

    async def __call__(self, prompt: str) -> str:
        if self.halt_reason is not None:
            return HALTED
        async with self._slots:
            # Re-check after waiting for a slot: the switch may have tripped meanwhile.
            self.halt_reason = self.halt_reason or self._admit()
            if self.halt_reason is not None:
                return HALTED
            self._budget.enter()
            try:
                self.sent += 1
                return await self._evaluate(prompt)
            finally:
                self._budget.leave()


def finalize(summary, guard: GuardedEvaluator):
    """Report only what was actually sent, and why the campaign stopped early."""
    kept = tuple(c for c in summary.candidates if c.response_sample != HALTED)
    return dataclasses.replace(
        summary, candidates=kept, candidates_evaluated=guard.sent,
        findings=sum(c.fitness_score >= 0.7 for c in kept),
        best_score=max((c.fitness_score for c in kept), default=0.0),
        halt_reason=guard.halt_reason.value if guard.halt_reason else None)
