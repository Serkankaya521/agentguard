"""Egress (response-side) secret-leak detection (B-R2).

Scans an agent/tool RESPONSE for secret disclosure before it reaches the user.

- Strongest signal (our edge, low false-positive): a known tenant secret/canary
  present in the response but ABSENT from the request — deterministic proof, via
  the shared secret_normalize (plain + base64 + hex + homoglyph/whitespace).
- Fallback: generic secret-shaped markers in the response.

Deterministic, ReDoS-safe (substring + str.translate only), length-capped, no
network/LLM/DB — safe on the hot path. Emits signals only; it does not decide.
Shadow/enforce behaviour and the per-policy flag are B-R3/B-R4.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

from enums import DetectorSeverity, ReasonCode
from bounded import DetectorSignal, MAX_TOTAL_CHARS, DEFAULT_BUDGET_US

from secret_normalize import canary_leaked

MAX_KNOWN_SECRETS = 64  # per-scan cap so a large secret set cannot blow the budget

# B-R3 egress guard modes. This is the per-policy `egress_secret_guard` flag; its
# storage in policy.schema.json + DB is Dev B's — here we only interpret the value.
OFF, SHADOW, ENFORCE = "off", "shadow", "enforce"
EGRESS_MODES = (OFF, SHADOW, ENFORCE)


class SecretLeakEgressDetector:
    detector_id = "secret_leak_egress"
    # Generic secret shapes, checked when no known-secret leak is found.
    _MARKERS = ("-----begin rsa private key", "-----begin private key",
                "aws_secret_access_key", "aws_session_token")

    def scan(self, response: str, known_secrets: Iterable[str] = (), request: str = "") -> list[DetectorSignal]:
        resp = (response or "")[:MAX_TOTAL_CHARS]
        req = (request or "")[:MAX_TOTAL_CHARS]
        # 1) Known secret/canary disclosed in the response but not supplied in the request.
        for secret in list(known_secrets)[:MAX_KNOWN_SECRETS]:
            if canary_leaked(secret, resp, req):
                return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_SECRET_EGRESS,
                                       DetectorSeverity.CRITICAL, 0.95,
                                       {"class": "secret_egress", "match": "known_secret"})]
        # 2) Fallback: generic secret-shaped content in the response.
        low = resp.lower()
        if any(m in low for m in self._MARKERS):
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_SECRET_EGRESS,
                                   DetectorSeverity.CRITICAL, 0.8,
                                   {"class": "secret_egress", "match": "generic_marker"})]
        return []


def default_egress_detectors() -> list[SecretLeakEgressDetector]:
    return [SecretLeakEgressDetector()]


@dataclass(frozen=True)
class EgressGuardResult:
    response: str          # B-R3 shadow never alters this; B-R4 enforce may replace/stop it
    signals: tuple
    mode: str
    would_block: bool
    applied: bool          # did we actually change/stop traffic? shadow -> always False (B-R4)


def evaluate_egress(response: str, known_secrets: Iterable[str] = (), request: str = "",
                    mode: str = SHADOW) -> EgressGuardResult:
    """B-R3: scan a response and compute the egress outcome WITHOUT altering traffic.
    off -> skip. shadow -> compute would_block; response passes unchanged (caller records a
    'would_block' event). shortcut: enforce masking/stop is B-R4, so until then enforce
    behaves like shadow (records, does not block)."""
    mode = mode if mode in EGRESS_MODES else SHADOW
    if mode == OFF:
        return EgressGuardResult(response, (), mode, False, False)
    signals = tuple(scan_response(response, known_secrets, request))
    would_block = any(s.reason_code == ReasonCode.DETECTOR_SECRET_EGRESS for s in signals)
    return EgressGuardResult(response, signals, mode, would_block, False)


def scan_response(response: str, known_secrets: Iterable[str] = (), request: str = "",
                  detectors: list | None = None, budget_us: int = DEFAULT_BUDGET_US) -> list[DetectorSignal]:
    """Run egress detectors with the same fail-safe/budget guard as the inbound runner:
    a detector that raises or overruns yields DETECTOR_BUDGET_EXCEEDED, never crashes the
    response path."""
    secrets = tuple(known_secrets)
    signals: list[DetectorSignal] = []
    for det in (detectors if detectors is not None else default_egress_detectors()):
        start = time.perf_counter_ns()
        try:
            out = det.scan(response, secrets, request)
        except Exception:
            out = [DetectorSignal(det.detector_id, ReasonCode.DETECTOR_BUDGET_EXCEEDED,
                                  DetectorSeverity.MEDIUM, 0.3, {"error": "detector_raised"})]
        if (time.perf_counter_ns() - start) // 1000 > budget_us:
            out = list(out) + [DetectorSignal(det.detector_id, ReasonCode.DETECTOR_BUDGET_EXCEEDED,
                                              DetectorSeverity.MEDIUM, 0.3, {"budget_us": budget_us})]
        signals.extend(out)
    return signals
