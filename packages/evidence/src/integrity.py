"""Evidence integrity: content hash, optional HMAC signature, tamper-evident chain.

Evidence and audit records must be immutable or tamper-evident (AGENTS.md #10).
The hash covers the record minus its own hash/signature; a prev_hash links
records into an append-only chain so tampering is detectable.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from serialization import canonical_json  # packages/contracts/src

_EXCLUDED = ("integrity_hash", "signature")


def _signable(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in _EXCLUDED}


def content_hash(record: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(_signable(record)).encode("utf-8")).hexdigest()


def sign(record: dict, key: Optional[object]) -> Optional[str]:
    if key is None:
        return None
    kb = key if isinstance(key, bytes) else str(key).encode("utf-8")
    h = record.get("integrity_hash") or content_hash(record)
    return "hmac-sha256:" + hmac.new(kb, h.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(record: dict, key: Optional[object] = None) -> tuple[bool, str]:
    if record.get("integrity_hash") != content_hash(record):
        return False, "integrity_hash mismatch (tampered)"
    if key is not None:
        want = sign(record, key)
        if not hmac.compare_digest(str(record.get("signature")), str(want)):
            return False, "signature mismatch"
    return True, "ok"


def verify_chain(records: list[dict], key: Optional[object] = None) -> tuple[bool, str]:
    """Records ordered oldest->newest; each prev_hash must match the prior hash."""
    prev = None
    for r in records:
        ok, reason = verify(r, key)
        if not ok:
            return False, f"{r.get('evidence_id')}: {reason}"
        if r.get("prev_hash") != prev:
            return False, f"{r.get('evidence_id')}: broken chain link"
        prev = r["integrity_hash"]
    return True, "ok"
