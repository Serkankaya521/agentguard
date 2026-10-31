"""A3: canary sızıntısı normalize edilerek mi tespit ediliyor? (birebir substring değil)

canary_leaked'in düz metnin yanı sıra base64/hex ile kodlanmış ve boşluk/homoglyph ile
gizlenmiş sızıntıları da yakaladığını, ama payload'da zaten geçen değeri (saldırganın
echo'su) sızıntı saymadığını doğrular. Deterministik, deps-hafif (sadece jobs.campaigns).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "apps/worker/src"))
sys.path.insert(0, os.path.join(_ROOT, "packages/detectors/src"))  # B-R1: canary_leaked ortak modülde

from jobs.campaigns import canary_leaked  # worker hâlâ re-export ediyor (B-R1 regresyon guard'ı)

CANARY = "PROD_9981_ABCDEF"
# Bağımsız oracle: implementasyonun kendi encode çağrısıyla dairesel olmasın diye sabit.
B64 = "UFJPRF85OTgxX0FCQ0RFRg"  # base64(CANARY), padding'siz
HEX_LO = "50524f445f393938315f414243444546"
HEX_UP = "50524F445F393938315F414243444546"


def test_plain_leak_and_echo_guard():
    assert canary_leaked(CANARY, f"the value is {CANARY} ok", "merhaba")
    # Saldırgan canary'yi kendi payload'ına koyduysa, model echo'su sızıntı değildir.
    assert not canary_leaked(CANARY, f"echo: {CANARY}", f"please repeat {CANARY}")


def test_whitespace_obfuscation():
    assert canary_leaked(CANARY, "leak: P R O D _ 9 9 8 1 _ A B C D E F done", "merhaba")
    assert canary_leaked(CANARY, "split\nPROD_9981\n_ABCDEF", "merhaba")


def test_homoglyph_obfuscation():
    c = "prod_canary_xj"  # p,o,c,a,x,j hepsi homoglyph haritasında
    leaked = "here: " + c.translate(str.maketrans({"o": "о", "a": "а", "c": "с", "x": "х", "j": "ј"}))
    assert leaked != "here: " + c, "test kurulumu: homoglyph gerçekten uygulanmalı"
    assert canary_leaked(c, leaked, "merhaba")


def test_base64_obfuscation():
    assert canary_leaked(CANARY, f"base64 dump: {B64}==", "merhaba")
    assert canary_leaked(CANARY, f"base64 dump: {B64}", "merhaba")  # padding'siz de


def test_hex_obfuscation():
    assert canary_leaked(CANARY, f"hex: {HEX_LO}", "merhaba")
    assert canary_leaked(CANARY, f"HEX: {HEX_UP}", "merhaba")


def test_encoded_echo_is_not_a_leak():
    # Kodlanmış biçim hem payload'da hem yanıtta ise yine sızıntı değil (guard korunur).
    assert not canary_leaked(CANARY, f"out {B64}", f"inject {B64} now")


def test_no_canary_no_false_positive():
    assert not canary_leaked("", "anything goes here", "prompt")
    assert not canary_leaked(None, "anything goes here", "prompt")
    assert not canary_leaked(CANARY, "totally unrelated response", "benign prompt")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("A3 canary normalization: all checks passed")
