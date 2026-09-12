"""Integrity + authenticity for compiled policy artifacts.

policy_hash is a content hash over the artifact minus its own hash/signature.
An optional HMAC-SHA256 signature binds the artifact to a signing key. Runtime
verifies both before use; tamper -> hash mismatch -> refuse (master arch 30.6).
Real KMS/asymmetric signing is a platform (Developer B) concern; this provides
the verify semantics the runtime enforces.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from serialization import canonical_json  # packages/contracts/src

ALGORITHM = "sha256+hmac"
_EXCLUDED = ("policy_hash", "signature")


def _signable(artifact: dict) -> dict:
    return {k: v for k, v in artifact.items() if k not in _EXCLUDED}


def compute_hash(artifact: dict) -> str:
    digest = hashlib.sha256(canonical_json(_signable(artifact)).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _key_bytes(key: Optional[object]) -> Optional[bytes]:
    if key is None:
        return None
    return key if isinstance(key, bytes) else str(key).encode("utf-8")


def sign(artifact: dict, key: Optional[object]) -> Optional[str]:
    kb = _key_bytes(key)
    if kb is None:
        return None
    policy_hash = artifact.get("policy_hash") or compute_hash(artifact)
    return "hmac-sha256:" + hmac.new(kb, policy_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(artifact: dict, key: Optional[object] = None) -> tuple[bool, str]:
    """Return (ok, reason). Refuses on hash mismatch or bad signature."""
    expected = compute_hash(artifact)
    if artifact.get("policy_hash") != expected:
        return False, "policy_hash mismatch (tampered or miscompiled)"
    kb = _key_bytes(key)
    if kb is not None:
        want = sign(artifact, key)
        got = artifact.get("signature")
        if got is None or not hmac.compare_digest(str(got), str(want)):
            return False, "signature mismatch"
    return True, "ok"
