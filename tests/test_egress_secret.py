"""B-R2: egress (cevap tarafı) sır-sızıntı dedektörü.

SecretLeakEgressDetector'ın bilinen canary'yi (düz + gizlenmiş) cevapta yakaladığını,
ama gelen istekte de geçiyorsa (kullanıcı verdiyse) sızıntı saymadığını; known secret
yoksa generic sır-şekli marker'a düştüğünü; scan_response'ın bir dedektör patlarsa
fail-safe DETECTOR_BUDGET_EXCEEDED döndüğünü doğrular. Deps-hafif (stdlib-only).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "packages/detectors/src"))
sys.path.insert(0, os.path.join(_ROOT, "packages/domain/src"))

from enums import DetectorSeverity, ReasonCode
from egress import SecretLeakEgressDetector, scan_response

CANARY = "PROD_9981_ABCDEF"
D = SecretLeakEgressDetector()


def test_known_canary_leak_is_critical():
    sig = D.scan(f"...the value is {CANARY} ok", known_secrets=[CANARY], request="hava nasıl?")
    assert len(sig) == 1
    assert sig[0].reason_code == ReasonCode.DETECTOR_SECRET_EGRESS
    assert sig[0].severity == DetectorSeverity.CRITICAL
    assert sig[0].evidence["match"] == "known_secret"


def test_user_supplied_secret_is_not_a_leak():
    # Canary gelen istekte de var → model echo'su sızıntı değil (guard korunur).
    assert D.scan(f"echo: {CANARY}", known_secrets=[CANARY], request=f"repeat {CANARY}") == []


def test_obfuscated_canary_still_caught():
    # base64(CANARY) (A3 gücü, ortak modülden).
    b64 = "UFJPRF85OTgxX0FCQ0RFRg"
    sig = D.scan(f"leaked blob {b64}", known_secrets=[CANARY], request="merhaba")
    assert sig and sig[0].evidence["match"] == "known_secret"


def test_generic_marker_fallback_when_no_known_secret():
    sig = D.scan("here is AWS_SECRET_ACCESS_KEY=AKIA...", known_secrets=[], request="")
    assert sig and sig[0].evidence["match"] == "generic_marker"
    assert sig[0].severity == DetectorSeverity.CRITICAL


def test_benign_response_no_signal():
    assert D.scan("Bugün hava güneşli, yardımcı olabildim mi?", known_secrets=[CANARY], request="x") == []


def test_scan_response_is_fail_safe():
    class Boom:
        detector_id = "boom"
        def scan(self, response, known_secrets=(), request=""):
            raise RuntimeError("detector blew up")
    sig = scan_response("whatever", detectors=[Boom()])
    assert len(sig) == 1 and sig[0].reason_code == ReasonCode.DETECTOR_BUDGET_EXCEEDED


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("B-R2 egress secret detector: all checks passed")
