"""Behavioral anomaly detector (task plan 11 detector category).

Deterministic, bounded check against a per-identity baseline (expected
capabilities + rate). Heavy behavioral baselines are precomputed by AEGIS and
read as risk profiles; this is the fast, explicit-baseline check.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from bounded import DetectorSignal
from enums import DetectorSeverity, ReasonCode


@dataclass(frozen=True)
class BehaviorBaseline:
    identity_id: str
    expected_capabilities: frozenset[str] = field(default_factory=frozenset)
    max_rate_per_window: int = 100


class BehavioralAnomalyDetector:
    detector_id = "behavioral_anomaly"

    def detect(self, *, capability_id: Optional[str], baseline: Optional[BehaviorBaseline],
               recent_count: int = 0) -> list[DetectorSignal]:
        if baseline is None:
            return []  # no baseline -> nothing to compare against
        signals = []
        if (capability_id is not None and baseline.expected_capabilities
                and capability_id not in baseline.expected_capabilities):
            signals.append(DetectorSignal(
                self.detector_id, ReasonCode.DETECTOR_BEHAVIORAL_ANOMALY,
                DetectorSeverity.HIGH, 0.7, {"reason": "unexpected_capability"}))
        if recent_count > baseline.max_rate_per_window:
            signals.append(DetectorSignal(
                self.detector_id, ReasonCode.DETECTOR_BEHAVIORAL_ANOMALY,
                DetectorSeverity.MEDIUM, 0.4, {"reason": "rate_anomaly"}))
        return signals
