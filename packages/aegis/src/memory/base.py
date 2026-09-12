"""Base AEGIS memory store.

Every memory type carries tenant/global scope, provenance, confidence, and
versioning, applies poisoning controls, and never grants privilege or deploy
authority (AGENTS.md #8; task plan 18). Unverified/low-trust knowledge is
quarantined and excluded from `established()` until promoted.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional

TRUST_THRESHOLD = 0.5
CONFIDENCE_THRESHOLD = 0.5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Provenance:
    source: str
    trust: float = 1.0  # 0..1 source trust score


@dataclass(frozen=True)
class MemoryRecord:
    record_id: str
    scope: str            # "global" or "tenant:<id>"
    memory_type: str
    key: str
    content: dict
    confidence: float
    provenance: Provenance
    verified: bool
    version: int
    created_at: str
    updated_at: str


class BaseMemory:
    memory_type = "base"

    def __init__(self, max_per_key: int = 50) -> None:
        self._max_per_key = max_per_key
        self._by_id: dict[str, MemoryRecord] = {}
        self._index: dict[tuple[str, str], list[str]] = {}  # (scope,key)->[record_id]

    @staticmethod
    def _scope(tenant_id: Optional[str]) -> str:
        return "global" if tenant_id is None else f"tenant:{tenant_id}"

    def add(self, *, key: str, content: dict, confidence: float, provenance: Provenance,
            tenant_id: Optional[str] = None, verified: bool = False) -> MemoryRecord:
        scope = self._scope(tenant_id)
        idx = self._index.setdefault((scope, key), [])
        version = (self._by_id[idx[-1]].version + 1) if idx else 1
        rec = MemoryRecord(
            record_id=f"mem-{uuid.uuid4()}", scope=scope, memory_type=self.memory_type,
            key=key, content=dict(content), confidence=float(confidence),
            provenance=provenance, verified=bool(verified), version=version,
            created_at=_now(), updated_at=_now())
        self._by_id[rec.record_id] = rec
        idx.append(rec.record_id)
        while len(idx) > self._max_per_key:  # bounded retention
            self._by_id.pop(idx.pop(0), None)
        return rec

    def get(self, record_id: str) -> Optional[MemoryRecord]:
        return self._by_id.get(record_id)

    def query(self, tenant_id: Optional[str], key: Optional[str] = None) -> list[MemoryRecord]:
        """Visible = this tenant's scope + global. Never another tenant's data."""
        scopes = {"global", self._scope(tenant_id)} if tenant_id is not None else {"global"}
        out = [r for r in self._by_id.values()
               if r.scope in scopes and (key is None or r.key == key)]
        return sorted(out, key=lambda r: (r.key, r.version), reverse=True)

    def established(self, tenant_id: Optional[str], key: Optional[str] = None) -> list[MemoryRecord]:
        """Only verified, sufficiently trusted, sufficiently confident knowledge."""
        return [r for r in self.query(tenant_id, key)
                if r.verified and r.confidence >= CONFIDENCE_THRESHOLD
                and r.provenance.trust >= TRUST_THRESHOLD]

    def quarantined(self, tenant_id: Optional[str]) -> list[MemoryRecord]:
        return [r for r in self.query(tenant_id) if not r.verified]

    def promote(self, record_id: str, *, verifier: str) -> Optional[MemoryRecord]:
        """Human/governance promotion. Learning cannot self-promote silently."""
        rec = self._by_id.get(record_id)
        if rec is None:
            return None
        promoted = replace(rec, verified=True, version=rec.version + 1, updated_at=_now(),
                           content={**rec.content, "_verified_by": verifier})
        self._by_id[promoted.record_id if False else record_id] = promoted
        return promoted
