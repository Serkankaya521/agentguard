"""Bounded, deterministic detector framework for the hot path.

Detectors are deterministic, ReDoS-safe (substring/token scans over
length-capped input), network/LLM/DB-free, and time-bounded. A detector that
raises or overruns its budget yields a safe DETECTOR_BUDGET_EXCEEDED signal
rather than crashing the request. Detectors only emit signals; the policy
evaluator owns the decision.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from enums import DetectorSeverity, ReasonCode

MAX_VALUE_CHARS = 4096          # per-value scan cap (ReDoS/complexity guard)
MAX_TOTAL_CHARS = 64 * 1024     # per-request total scan cap
DEFAULT_BUDGET_US = 500         # per-detector soft budget


@dataclass(frozen=True)
class DetectorSignal:
    detector_id: str
    reason_code: ReasonCode
    severity: DetectorSeverity
    risk: float                     # 0..1 contribution
    evidence: dict = field(default_factory=dict)  # small labels only, never raw payload


@dataclass(frozen=True)
class DetectionInput:
    tool_id: str
    resource_scope: Optional[str]
    values: tuple[str, ...]         # canonicalized, length-capped string values


def flatten(arguments: dict, resource_scope: Optional[str]) -> DetectionInput:
    """Flatten argument values into capped strings for scanning."""
    values: list[str] = []
    total = 0
    def add(v: object) -> None:
        nonlocal total
        if total >= MAX_TOTAL_CHARS:
            return
        s = v if isinstance(v, str) else str(v)
        s = s[:MAX_VALUE_CHARS]
        total += len(s)
        values.append(s)
    def walk(o: object) -> None:
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        else:
            add(o)
    walk(arguments or {})
    if resource_scope:
        add(resource_scope)
    return DetectionInput(tool_id="", resource_scope=resource_scope, values=tuple(values))


class Detector:
    detector_id: str = "base"

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:  # pragma: no cover
        raise NotImplementedError


class DetectorRunner:
    def __init__(self, detectors: list[Detector], budget_us: int = DEFAULT_BUDGET_US) -> None:
        self._detectors = detectors
        self._budget_us = budget_us

    def run(self, arguments: dict, resource_scope: Optional[str],
            tool_id: str = "") -> list[DetectorSignal]:
        data = flatten(arguments, resource_scope)
        data = DetectionInput(tool_id=tool_id, resource_scope=resource_scope, values=data.values)
        signals: list[DetectorSignal] = []
        for det in self._detectors:
            start = time.perf_counter_ns()
            try:
                out = det.detect(data)
            except Exception:
                out = [DetectorSignal(det.detector_id, ReasonCode.DETECTOR_BUDGET_EXCEEDED,
                                      DetectorSeverity.MEDIUM, 0.3, {"error": "detector_raised"})]
            elapsed = (time.perf_counter_ns() - start) // 1000
            if elapsed > self._budget_us:
                out = list(out) + [DetectorSignal(
                    det.detector_id, ReasonCode.DETECTOR_BUDGET_EXCEEDED,
                    DetectorSeverity.MEDIUM, 0.3, {"budget_us": self._budget_us, "elapsed_us": elapsed})]
            signals.extend(out)
        return signals


def max_severity(signals: list[DetectorSignal]) -> Optional[DetectorSeverity]:
    order = {DetectorSeverity.LOW: 1, DetectorSeverity.MEDIUM: 2,
             DetectorSeverity.HIGH: 3, DetectorSeverity.CRITICAL: 4}
    if not signals:
        return None
    return max((s.severity for s in signals), key=lambda sev: order[sev])
