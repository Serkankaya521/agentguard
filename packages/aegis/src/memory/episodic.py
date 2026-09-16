"""Episodic memory: past attacks, attempts, and outcomes."""
from __future__ import annotations

from memory.base import BaseMemory, Provenance


class EpisodicMemory(BaseMemory):
    memory_type = "episodic"

    def record_attempt(self, *, tenant_id, technique: str, outcome: str, evidence_backed: bool,
                       confidence: float = 0.6, source: str = "red_team"):
        return self.add(tenant_id=tenant_id, key=technique,
                        content={"outcome": outcome, "evidence_backed": evidence_backed},
                        confidence=confidence, provenance=Provenance(source, trust=0.8),
                        verified=evidence_backed)
