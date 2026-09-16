"""Shadow/canary evaluation with security metrics (task plan 40; master arch 16).

Computes real detection metrics (false-positive rate, detection rate, precision,
latency p99) for a candidate detector/policy against a labeled corpus, and gates
promotion. Shadow evaluates offline; canary evaluates on a bounded traffic sample.
These results feed the governance SHADOW/CANARY stages.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class EvalMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    fpr: float
    detection_rate: float
    precision: float
    latency_p99_us: int
    total: int


@dataclass(frozen=True)
class GateThresholds:
    max_fpr: float = 0.05
    min_detection_rate: float = 0.90
    max_latency_p99_us: int = 10_000


@dataclass(frozen=True)
class EvalResult:
    metrics: EvalMetrics
    passed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def evaluate(flag: Callable[[dict], bool], labeled: list[dict]) -> EvalMetrics:
    """labeled items: {"sample": ..., "malicious": bool}. flag(sample) -> flagged."""
    tp = fp = fn = tn = 0
    latencies = []
    for item in labeled:
        start = time.perf_counter_ns()
        flagged = bool(flag(item["sample"]))
        latencies.append((time.perf_counter_ns() - start) // 1000)
        mal = bool(item["malicious"])
        if flagged and mal:
            tp += 1
        elif flagged and not mal:
            fp += 1
        elif not flagged and mal:
            fn += 1
        else:
            tn += 1
    latencies.sort()
    p99 = latencies[min(len(latencies) - 1, int(0.99 * len(latencies)))] if latencies else 0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
    detection = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    return EvalMetrics(tp, fp, fn, tn, fpr, detection, precision, int(p99), len(labeled))


def _gate(metrics: EvalMetrics, thresholds: GateThresholds) -> EvalResult:
    reasons = []
    if metrics.fpr > thresholds.max_fpr:
        reasons.append("fpr_too_high")
    if metrics.detection_rate < thresholds.min_detection_rate:
        reasons.append("detection_rate_too_low")
    if metrics.latency_p99_us > thresholds.max_latency_p99_us:
        reasons.append("latency_regression")
    return EvalResult(metrics, not reasons, tuple(reasons))


class ShadowEvaluator:
    """Offline shadow evaluation over the full labeled corpus (no enforcement)."""
    def run(self, flag: Callable[[dict], bool], labeled: list[dict],
            thresholds: GateThresholds = GateThresholds()) -> EvalResult:
        return _gate(evaluate(flag, labeled), thresholds)


class CanaryEvaluator:
    """Bounded-traffic canary evaluation over a deterministic sample."""
    def run(self, flag: Callable[[dict], bool], labeled: list[dict],
            thresholds: GateThresholds = GateThresholds(),
            sample_fraction: float = 0.1, seed: int = 0) -> EvalResult:
        rng = random.Random(seed)
        k = max(1, int(len(labeled) * sample_fraction))
        sample = rng.sample(labeled, min(k, len(labeled)))
        return _gate(evaluate(flag, sample), thresholds)
