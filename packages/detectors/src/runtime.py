"""Deterministic runtime detectors (attack-pattern based, not keyword based).

Each scans length-capped, canonicalized input for concrete attack indicators and
emits a stable reason code. Benign input (e.g. "select 1") produces no signal.
"""
from __future__ import annotations

from enums import DetectorSeverity, ReasonCode
from bounded import DetectionInput, Detector, DetectorSignal


def _any(values, needles) -> bool:
    for v in values:
        low = v.lower()
        for n in needles:
            if n in low:
                return True
    return False


class SqlInjectionDetector(Detector):
    detector_id = "sql_injection"
    _MARKERS = (" or 1=1", "' or '", "\" or \"", " union select ", "union select(",
                "; drop ", "; delete ", "'--", "' --", "/*", "xp_cmdshell", "' or 1=1")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        if _any(data.values, self._MARKERS):
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_SQL_INJECTION,
                                   DetectorSeverity.HIGH, 0.8, {"class": "sqli"})]
        return []


class PathTraversalDetector(Detector):
    detector_id = "path_traversal"
    _MARKERS = ("../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow", "/proc/self/environ")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        hits = [m for m in self._MARKERS if _any(data.values, (m,))]
        if not hits:
            return []
        crit = any(h in ("/etc/shadow", "/proc/self/environ") for h in hits)
        sev = DetectorSeverity.CRITICAL if crit else DetectorSeverity.HIGH
        return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_PATH_TRAVERSAL,
                               sev, 0.85 if crit else 0.75, {"class": "path"})]


class SsrfDetector(Detector):
    detector_id = "ssrf"
    _MARKERS = ("169.254.169.254", "file://", "gopher://", "127.0.0.1", "localhost",
                "metadata.google.internal", "::1")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        if _any(data.values, self._MARKERS):
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_SSRF,
                                   DetectorSeverity.HIGH, 0.8, {"class": "ssrf"})]
        return []


class SecretAccessDetector(Detector):
    detector_id = "secret_access"
    _MARKERS = ("-----begin rsa private key", "-----begin private key",
                "aws_secret_access_key", "aws_session_token")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        if _any(data.values, self._MARKERS):
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_SECRET_ACCESS,
                                   DetectorSeverity.CRITICAL, 0.9, {"class": "secret"})]
        return []


class CommandInjectionDetector(Detector):
    detector_id = "command_injection"
    _MARKERS = ("$(", "`", "&&", "|| ", "; rm ", "rm -rf", "wget http", "curl http",
                "; cat ", "nc -e", "bash -i")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        if _any(data.values, self._MARKERS):
            crit = _any(data.values, ("rm -rf /", "nc -e", "bash -i"))
            sev = DetectorSeverity.CRITICAL if crit else DetectorSeverity.HIGH
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_COMMAND_INJECTION,
                                   sev, 0.85 if crit else 0.75, {"class": "cmd"})]
        return []


class PromptInjectionDetector(Detector):
    detector_id = "prompt_injection"
    _MARKERS = ("ignore previous instructions", "ignore all previous", "disregard the above",
                "you are now", "reveal your system prompt", "exfiltrate", "override your policy")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        if _any(data.values, self._MARKERS):
            return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_PROMPT_INJECTION,
                                   DetectorSeverity.HIGH, 0.7, {"class": "prompt_injection"})]
        return []


class DataExfilDetector(Detector):
    detector_id = "data_exfil"
    _B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

    def detect(self, data: DetectionInput) -> list[DetectorSignal]:
        for v in data.values:
            run = 0
            for ch in v:
                run = run + 1 if ch in self._B64 else 0
                if run >= 512:  # long base64-looking blob -> possible exfil
                    return [DetectorSignal(self.detector_id, ReasonCode.DETECTOR_DATA_EXFIL,
                                           DetectorSeverity.MEDIUM, 0.4, {"class": "exfil_blob"})]
        return []


def default_detectors() -> list[Detector]:
    return [
        SqlInjectionDetector(), PathTraversalDetector(), SsrfDetector(),
        SecretAccessDetector(), CommandInjectionDetector(), PromptInjectionDetector(),
        DataExfilDetector(),
    ]
