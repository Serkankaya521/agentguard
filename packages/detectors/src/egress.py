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

from secret_normalize import canary_leaked, mask_secrets

MAX_KNOWN_SECRETS = 64  # per-scan cap so a large secret set cannot blow the budget

# B-R3 egress guard modes. This is the per-policy `egress_secret_guard` flag; its
# storage in policy.schema.json + DB is Dev B's — here we only interpret the value.
OFF, SHADOW, ENFORCE = "off", "shadow", "enforce"
EGRESS_MODES = (OFF, SHADOW, ENFORCE)

# B-R4 enforce actions (also a per-policy flag owned by Dev B). mask is preferred.
MASK, STOP = "mask", "stop"
ENFORCE_ACTIONS = (MASK, STOP)
SAFE_MESSAGE = "[response withheld: potential secret disclosure]"


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


def _enforce(response: str, known_secrets, request: str, action: str) -> tuple[str, bool]:
    """Apply enforcement to a response already known to leak (B-R4). Returns (response, True).
    mask: redact every literal secret form, then RE-SCAN; if anything still leaks (obfuscated
    form or a generic marker we cannot pinpoint) fall back to stop, so a secret never passes."""
    if action == STOP:
        return SAFE_MESSAGE, True
    masked = mask_secrets(response, known_secrets)
    still = scan_response(masked, known_secrets, request)
    if any(s.reason_code == ReasonCode.DETECTOR_SECRET_EGRESS for s in still):
        return SAFE_MESSAGE, True
    return masked, True


def evaluate_egress(response: str, known_secrets: Iterable[str] = (), request: str = "",
                    mode: str = SHADOW, action: str = MASK) -> EgressGuardResult:
    """Scan a response and compute the egress outcome.
    off -> skip. shadow -> compute would_block; response passes UNCHANGED (caller records a
    'would_block' event). enforce (B-R4) -> on a leak, mask the secret or stop the response;
    `action` (mask|stop) is a per-policy flag owned by Dev B, default mask."""
    mode = mode if mode in EGRESS_MODES else SHADOW
    if mode == OFF:
        return EgressGuardResult(response, (), mode, False, False)
    signals = tuple(scan_response(response, known_secrets, request))
    would_block = any(s.reason_code == ReasonCode.DETECTOR_SECRET_EGRESS for s in signals)
    if mode == ENFORCE and would_block:
        action = action if action in ENFORCE_ACTIONS else MASK
        new_response, applied = _enforce(response, known_secrets, request, action)
        return EgressGuardResult(new_response, signals, mode, would_block, applied)
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
