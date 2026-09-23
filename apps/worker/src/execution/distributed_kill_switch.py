"""Distributed in-flight kill switch (task plan; handoff Developer A item).

The in-process KillSwitch stops only the worker that holds it. A campaign runs
across instances, so a trip must be visible everywhere at once. This mirrors the
KillSwitch interface (is_tripped/trip/recover) over a shared store (e.g. Redis),
so an operator tripping it on any instance halts every in-flight campaign.

Semantics:
- Fail safe. If the backend cannot be read, an in-flight campaign is NOT authorised
  to continue, so is_tripped() returns True on a backend error. Uncertainty stops
  the attack; it never lets it run on.
- Responsive but bounded. is_tripped() is checked before every request; a short
  per-scope cache (default 1s) bounds backend load while keeping a trip effective
  within the cache window. A positive (tripped) result is never cached away — once
  seen tripped it stays tripped until recover() and the next read confirms.
- Durable + audited. trip()/recover() write through to the store (the durable record)
  and append to an in-process audit log; they surface backend failures to the caller,
  because a trip that did not persist must not look engaged.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Optional

_SAFE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
GLOBAL = "global"


def _key(scope: str) -> str:
    if not _SAFE.fullmatch(scope):
        raise ValueError("unsafe kill-switch scope")
    return "ag:kill:" + scope


class DistributedKillSwitch:
    def __init__(self, client, *, clock=None, cache_ttl_s: float = 1.0,
                 fail_safe: bool = True) -> None:
        self._client = client
        self._clock = clock or time.monotonic
        self._cache_ttl_s = cache_ttl_s
        self._fail_safe = fail_safe
        self._negative_until: dict[str, float] = {}  # key -> expiry; only NOT-tripped is cached
        self.audit_log: list[dict] = []

    # --- scope helpers --------------------------------------------------------
    @staticmethod
    def _scope(campaign_id=None, tenant_id=None, global_=False) -> str:
        if global_:
            return GLOBAL
        if tenant_id:
            return f"tenant:{tenant_id}"
        return f"campaign:{campaign_id}"

    def _audit(self, op: str, scope: str, actor: str) -> None:
        self.audit_log.append({"op": op, "scope": scope, "actor": actor,
                               "at": datetime.now(timezone.utc).isoformat()})

    # --- mutations (surface backend failure to the operator) ------------------
    def trip(self, *, actor: str, campaign_id=None, tenant_id=None, global_=False) -> None:
        scope = self._scope(campaign_id, tenant_id, global_)
        record = json.dumps({"actor": actor, "at": datetime.now(timezone.utc).isoformat()},
                            separators=(",", ":"))
        self._client.set(_key(scope), record)
        self._negative_until.pop(_key(scope), None)  # a stale "not tripped" must not linger
        self._audit("trip", scope, actor)

    def recover(self, *, actor: str, campaign_id=None, tenant_id=None, global_=False) -> None:
        scope = self._scope(campaign_id, tenant_id, global_)
        self._client.delete(_key(scope))
        self._negative_until.pop(_key(scope), None)  # force a fresh read next check
        self._audit("recover", scope, actor)

    # --- checks (fail safe) ---------------------------------------------------
    def _is_set(self, key: str) -> bool:
        # Only the common NOT-tripped result is cached, to bound backend load. A
        # tripped result is always re-read so a recover propagates within one check.
        now = self._clock()
        until = self._negative_until.get(key)
        if until is not None and until > now:
            return False
        if self._client.get(key) is not None:
            self._negative_until.pop(key, None)
            return True
        self._negative_until[key] = now + self._cache_ttl_s
        return False

    def is_tripped(self, *, campaign_id=None, tenant_id=None) -> bool:
        try:
            if self._is_set(_key(GLOBAL)):
                return True
            if tenant_id and self._is_set(_key(f"tenant:{tenant_id}")):
                return True
            if campaign_id and self._is_set(_key(f"campaign:{campaign_id}")):
                return True
            return False
        except Exception:
            # Cannot confirm the switch state -> do not authorise continuation.
            return self._fail_safe
