"""Kill switch with campaign/tenant/global scopes (task plan 25).

Fast (dict lookup), audited, checked by active jobs at every step, and cannot be
silently disabled - recovery is explicit and audited.
"""
from __future__ import annotations

from datetime import datetime, timezone


class KillSwitch:
    GLOBAL = "global"

    def __init__(self) -> None:
        self._tripped: set[str] = set()
        self.audit_log: list[dict] = []

    def _audit(self, op: str, scope: str, actor: str) -> None:
        self.audit_log.append({"op": op, "scope": scope, "actor": actor,
                               "at": datetime.now(timezone.utc).isoformat()})

    def trip(self, *, actor: str, campaign_id=None, tenant_id=None, global_=False) -> None:
        scope = (self.GLOBAL if global_ else
                 f"tenant:{tenant_id}" if tenant_id else f"campaign:{campaign_id}")
        self._tripped.add(scope)
        self._audit("trip", scope, actor)

    def recover(self, *, actor: str, campaign_id=None, tenant_id=None, global_=False) -> None:
        scope = (self.GLOBAL if global_ else
                 f"tenant:{tenant_id}" if tenant_id else f"campaign:{campaign_id}")
        self._tripped.discard(scope)
        self._audit("recover", scope, actor)

    def is_tripped(self, *, campaign_id=None, tenant_id=None) -> bool:
        if self.GLOBAL in self._tripped:
            return True
        if tenant_id and f"tenant:{tenant_id}" in self._tripped:
            return True
        if campaign_id and f"campaign:{campaign_id}" in self._tripped:
            return True
        return False


class KillSwitchTripped(RuntimeError):
    pass
