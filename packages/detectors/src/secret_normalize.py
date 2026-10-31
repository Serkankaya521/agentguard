"""Shared, single-source secret/canary leak detection (A3 logic, extracted in B-R1).

Deterministic, ReDoS-safe (substring + str.translate only, no regex, no network/LLM),
so it is safe on the runtime hot path. Used by the worker campaign promotion
(apps/worker/src/jobs/campaigns.py) and the runtime egress detector (B-R2) so both
sides share one implementation instead of a copy each.
"""
from __future__ import annotations

import base64

# Cyrillic look-alikes → ASCII (mirror of core MutationOperators.HOMOGLYPH_MAP, reversed).
_HOMOGLYPHS = str.maketrans({'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j',
                             'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y'})


def _fold(text):
    """Fold Cyrillic look-alikes to ASCII and drop all whitespace so spaced/homoglyph leaks still match."""
    return ''.join(text.translate(_HOMOGLYPHS).split())


def secret_variants(secret):
    """The literal forms a secret can appear as: plain, base64 (no padding), lower/upper hex.
    Homoglyph/whitespace obfuscation is matched by folding, not by a literal variant."""
    if not secret:
        return ()
    b = secret.encode()
    return tuple(dict.fromkeys(v for v in (secret, base64.b64encode(b).decode().rstrip('='),
                                           b.hex(), b.hex().upper()) if v))


def canary_leaked(canary, response, prompt=''):
    """True when the server-side canary is disclosed in the response but was absent from the attack payload.
    Catches plain, base64, hex and homoglyph/whitespace-obfuscated disclosure. ReDoS-safe: substring and
    str.translate only, no regex. shortcut: base64/hex match the canary encoded on its own, not embedded in a
    larger encoded blob (3-byte alignment); widen if targets begin encoding whole responses."""
    if not canary:
        return False
    for v in secret_variants(canary):
        if v in response and v not in prompt:
            return True
    f = _fold(canary)
    return bool(f) and f in _fold(response) and f not in _fold(prompt)


def mask_secrets(text, secrets, mask='****'):
    """Replace every literal (plain/base64/hex) occurrence of each known secret with `mask`.
    Homoglyph/whitespace-obfuscated forms are NOT located here; the caller must re-scan the
    masked text and stop the response if anything still leaks."""
    for secret in secrets:
        for v in secret_variants(secret):
            if v in text:
                text = text.replace(v, mask)
    return text
