"""Precomputed risk lookup (master arch 30.8).

AEGIS publishes versioned risk profiles asynchronously; the runtime only reads
them from cache. It never queries AEGIS synchronously and never treats a profile
as verified fact. Stale or missing profiles fall back to a policy-defined default
(no escalation) rather than fabricating risk.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

HIGH_RISK_THRESHOLD = 0.70
MIN_CONFIDENCE = 0.50


@dataclass(frozen=True)
class RiskProfile:
    subject_type: str
    subject_id: str
    tenant_id: str
    environment: str
    risk_score: float
    confidence: float
    source: str
    version: str
    generated_at: str
    expires_at: Optional[str] = None
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "1.0.0"
    # monotonic expiry used for freshness on the hot path (set by publisher)
    _expiry_monotonic: float = 0.0


@dataclass(frozen=True)
class RiskLookup:
    profile: Optional[RiskProfile]
    status: str          # "fresh" | "stale" | "missing"

    @property
    def is_high(self) -> bool:
        return (
            self.status == "fresh"
            and self.profile is not None
            and self.profile.confidence >= MIN_CONFIDENCE
            and self.profile.risk_score >= HIGH_RISK_THRESHOLD
        )


class PrecomputedRiskStore:
    """Runtime-side read cache of AEGIS-published risk profiles."""

    def __init__(self, clock=None) -> None:
        self._clock = clock or time.monotonic
        self._by_key: dict[tuple[str, str, str], RiskProfile] = {}

    @staticmethod
    def _key(subject_type: str, subject_id: str, tenant_id: str) -> tuple[str, str, str]:
        return (subject_type, subject_id, tenant_id)

    def publish(self, profile: RiskProfile, ttl_s: float = 300.0) -> None:
        object.__setattr__(profile, "_expiry_monotonic", self._clock() + ttl_s if ttl_s > 0 else 0.0)
        self._by_key[self._key(profile.subject_type, profile.subject_id, profile.tenant_id)] = profile

    def lookup(self, subject_type: str, subject_id: str, tenant_id: str) -> RiskLookup:
        profile = self._by_key.get(self._key(subject_type, subject_id, tenant_id))
        if profile is None:
            return RiskLookup(None, "missing")
        expiry = getattr(profile, "_expiry_monotonic", 0.0)
        if expiry and self._clock() > expiry:
            return RiskLookup(profile, "stale")
        return RiskLookup(profile, "fresh")
