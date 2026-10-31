"""B-R3: egress shadow modu — hesapla + kaydet, trafiğe dokunma.

evaluate_egress'in off/shadow/enforce modlarında cevabı ASLA değiştirmediğini (shadow-safe),
sızıntıda would_block hesapladığını; AsyncEventPublisher.publish_egress_shadow'un off-hot-path
bir would_block olayı kaydettiğini ve bu olayda sırrın DEĞERİNİN yer almadığını doğrular.
Deps-hafif (stdlib-only: serialization + detectors).
"""
import json
import os
import sys
from types import SimpleNamespace

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("packages/detectors/src", "packages/domain/src", "packages/contracts/src",
          "apps/runtime-gateway/src"):
    sys.path.insert(0, os.path.join(_ROOT, p))

from egress import evaluate_egress, OFF, SHADOW, ENFORCE
from hot_path.event_publisher import AsyncEventPublisher  # serialization -> contracts (not the shim)

CANARY = "PROD_9981_ABCDEF"
RESP = f"...the value is {CANARY} ok"


def test_off_skips_and_passes_through():
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="x", mode=OFF)
    assert r.would_block is False and r.signals == () and r.response == RESP


def test_shadow_detects_but_never_alters_response():
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="hava nasıl?", mode=SHADOW)
    assert r.would_block is True
    assert r.applied is False          # shadow trafiğe dokunmaz
    assert r.response == RESP          # cevap aynen geçer


def test_enforce_now_applies_masking():
    # B-R4: enforce artık gerçekten müdahale eder (maskele); shadow'dan farkı burada.
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="x", mode=ENFORCE)
    assert r.would_block is True and r.applied is True
    assert CANARY not in r.response and "****" in r.response


def test_unknown_mode_defaults_to_shadow():
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="x", mode="bogus")
    assert r.mode == SHADOW


def test_no_leak_no_would_block():
    r = evaluate_egress("Bugün hava güzel.", known_secrets=[CANARY], request="x", mode=SHADOW)
    assert r.would_block is False


def _event():
    return SimpleNamespace(trace_id="t1", event_id="e1", payload_hash="h1",
                           tenant=SimpleNamespace(tenant_id="tnt1"))


def test_shadow_event_recorded_without_secret_value():
    pub = AsyncEventPublisher()
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="x", mode=SHADOW)
    assert pub.publish_egress_shadow(_event(), r) is True
    out = pub.drain()
    assert len(out) == 1
    rec = out[0]
    assert rec["kind"] == "telemetry"
    assert rec["summary"]["would_block"] is True and rec["summary"]["guard"] == "egress_secret"
    # Kritik güvenlik: kaydedilen olay sırrın DEĞERİNİ içermemeli (sadece reason/match).
    assert CANARY not in json.dumps(rec)


def test_shadow_event_is_idempotent():
    pub = AsyncEventPublisher()
    r = evaluate_egress(RESP, known_secrets=[CANARY], request="x", mode=SHADOW)
    ev = _event()
    assert pub.publish_egress_shadow(ev, r) is True
    assert pub.publish_egress_shadow(ev, r) is False   # aynı event -> deduped
    assert len(pub.drain()) == 1


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("B-R3 egress shadow: all checks passed")
