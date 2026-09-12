"""Risk-profile publisher (producer side of the A3 precomputed-risk consumer).

AEGIS derives risk profiles from memory/graph asynchronously and publishes
schema-valid RiskProfiles for the runtime to read from cache. Learning autonomy
does not grant privilege autonomy: this only proposes/publishes read profiles;
it never changes policy, privilege, or deployment.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from validation import validate  # packages/contracts/src


class RiskProfilePublisher:
    def __init__(self, sink: Optional[Callable[[dict], None]] = None) -> None:
        self._sink = sink

    def build_profile(self, *, subject_type: str, subject_id: str, tenant_id: str,
                      environment: str, risk_score: float, confidence: float,
                      reason_codes=None, source: str = "aegis", version: str = "1") -> dict:
        profile = {
            "schema_version": "1.0.0",
            "subject_type": subject_type, "subject_id": subject_id,
            "tenant_id": tenant_id, "environment": environment,
            "risk_score": round(float(risk_score), 4), "confidence": round(float(confidence), 4),
            "reason_codes": list(reason_codes or []), "source": source, "version": version,
            "generated_at": datetime.now(timezone.utc).isoformat(), "expires_at": None,
        }
        errors = validate(profile, "risk_profile")
        if errors:
            raise ValueError(f"invalid risk profile: {errors[:3]}")
        return profile

    def publish(self, profile: dict) -> dict:
        if validate(profile, "risk_profile"):
            raise ValueError("refusing to publish invalid risk profile")
        if self._sink is not None:
            self._sink(profile)
        return profile
