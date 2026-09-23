"""Make approval revocations effective at the runtime enforcement point.

The Control Plane emits an ``approval.revoked`` event (P1) carrying the nonces of
every token issued for a revoked request. This processor writes those nonces into
the shared replay guard, so the ExecutionGate denies them (EXEC_APPROVAL_REPLAY)
across every gateway instance — not just the one that first saw the token.

The processor is broker-agnostic: it takes a decoded event and a guard exposing
``revoke(tenant_id, nonce, *, ttl_s)`` (see control-api ApprovalReplayGuard). The
Kafka/Redis wiring lives in the thin consumer entrypoint.

TTL: the gate only ever *consumes* a nonce whose remaining lifetime is <= 24h (it
rejects longer-lived tokens as invalid), so a revocation held for the guard's 24h
maximum always outlives any nonce that could still be consumed. When the event
carries ``expires_at`` we honour it (clamped); otherwise we use the maximum.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Optional

REVOKED_EVENT_TYPE = "approval.revoked"
_MAX_TTL_S = 86_400  # the replay guard's bound; also our safe default (see module docstring)
# Same character class the guard enforces; a nonce outside it could never have been
# minted or consumed, so it is skipped rather than allowed to fail the whole event.
_SAFE_NONCE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


class RevocationBackendError(RuntimeError):
    """The guard backend failed (e.g. Redis unreachable).

    The caller must NOT commit the offset: the event has to be redelivered so the
    revocation is not silently lost. Revocation is idempotent, so replay is safe.
    """


@dataclass(frozen=True)
class RevocationResult:
    tenant_id: str
    request_id: Optional[str]
    revoked: int
    skipped: int  # malformed nonces that no real token could match


def _ttl_from(event: Mapping, now: float) -> int:
    expires_at = event.get("expires_at")
    if expires_at is None:
        return _MAX_TTL_S
    return max(1, min(_MAX_TTL_S, int(float(expires_at) - now)))


class ApprovalRevocationProcessor:
    def __init__(self, guard, *, clock=None) -> None:
        self._guard = guard
        import time
        self._clock = clock or time.time

    def process_event(self, event: Mapping) -> Optional[RevocationResult]:
        """Revoke every nonce in one event. Returns None for unrelated events.

        Raises RevocationBackendError if the guard backend fails, so the caller
        leaves the offset uncommitted for redelivery.
        """
        if event.get("event_type") not in (None, REVOKED_EVENT_TYPE):
            # Topic may be shared; ignore anything that is not a revocation.
            return None
        tenant_id = event.get("tenant_id")
        nonces = event.get("nonces")
        if not tenant_id or not isinstance(nonces, (list, tuple)):
            raise ValueError("malformed approval.revoked event")
        ttl_s = _ttl_from(event, self._clock())
        revoked = skipped = 0
        for nonce in nonces:
            if not isinstance(nonce, str) or not _SAFE_NONCE.fullmatch(nonce):
                skipped += 1
                continue
            try:
                self._guard.revoke(str(tenant_id), nonce, ttl_s=ttl_s)
            except ValueError:
                # Guard rejected the value itself (not a backend failure): skip it.
                skipped += 1
            except Exception as exc:  # backend down/timeout -> redeliver the event
                raise RevocationBackendError(type(exc).__name__) from exc
            else:
                revoked += 1
        return RevocationResult(str(tenant_id), event.get("request_id"), revoked, skipped)
