"""B-R4: egress enforce modu — maskele (tercih) veya durdur, sır asla geçmesin.

enforce'ta bilinen sırrın plain/base64/hex biçimlerinin '****' ile maskelendiğini; maskeleme
sonrası yeniden tarayıp hâlâ sızıntı varsa (homoglyph/boşluk gibi yeri saptanamayan biçim)
güvenli mesaja (stop) düştüğünü; stop aksiyonunun doğrudan güvenli mesaj döndüğünü; shadow'un
hâlâ cevabı değiştirmediğini doğrular. Deps-hafif (stdlib-only).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("packages/detectors/src", "packages/domain/src"):
    sys.path.insert(0, os.path.join(_ROOT, p))

from egress import evaluate_egress, SHADOW, ENFORCE, MASK, STOP, SAFE_MESSAGE
from secret_normalize import mask_secrets

CANARY = "PROD_9981_ABCDEF"


def test_mask_redacts_plain_secret_and_passes_rest():
    r = evaluate_egress(f"user asked; value={CANARY}; bye", known_secrets=[CANARY],
                        request="x", mode=ENFORCE, action=MASK)
    assert r.applied is True and r.would_block is True
    assert CANARY not in r.response and "****" in r.response
    assert "user asked" in r.response and "bye" in r.response  # kalan cevap geçer


def test_mask_redacts_base64_variant():
    b64 = "UFJPRF85OTgxX0FCQ0RFRg"  # base64(CANARY), padding'siz
    r = evaluate_egress(f"blob {b64} end", known_secrets=[CANARY], request="x",
                        mode=ENFORCE, action=MASK)
    assert r.applied is True and b64 not in r.response and "****" in r.response


def test_mask_falls_back_to_stop_when_obfuscated():
    # Homoglyph gizleme: literal biçim yok -> maskeleme saptayamaz -> güvenli mesaja düş.
    secret = "prod_canary_xj"
    leaked = "here: " + secret.translate(str.maketrans({"o": "о", "a": "а", "c": "с",
                                                        "x": "х", "j": "ј"}))
    r = evaluate_egress(leaked, known_secrets=[secret], request="x", mode=ENFORCE, action=MASK)
    assert r.applied is True and r.response == SAFE_MESSAGE


def test_stop_action_returns_safe_message():
    r = evaluate_egress(f"value {CANARY}", known_secrets=[CANARY], request="x",
                        mode=ENFORCE, action=STOP)
    assert r.applied is True and r.response == SAFE_MESSAGE


def test_enforce_no_leak_passes_unchanged():
    r = evaluate_egress("Bugün hava güzel.", known_secrets=[CANARY], request="x",
                        mode=ENFORCE, action=MASK)
    assert r.would_block is False and r.applied is False and r.response == "Bugün hava güzel."


def test_shadow_still_never_alters_response():
    resp = f"value {CANARY}"
    r = evaluate_egress(resp, known_secrets=[CANARY], request="x", mode=SHADOW, action=MASK)
    assert r.would_block is True and r.applied is False and r.response == resp


def test_mask_secrets_covers_plain_base64_hex():
    masked = mask_secrets(f"{CANARY} / UFJPRF85OTgxX0FCQ0RFRg / 50524f445f393938315f414243444546",
                          [CANARY])
    assert CANARY not in masked and "UFJPRF85OTgxX0FCQ0RFRg" not in masked
    assert "50524f445f393938315f414243444546" not in masked and masked.count("****") == 3


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("B-R4 egress enforce: all checks passed")
