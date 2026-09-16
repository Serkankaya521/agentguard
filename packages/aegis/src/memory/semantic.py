"""Semantic memory: validated external/internal security knowledge.

External threat intel is untrusted input: stored quarantined (unverified) with a
source trust score until promoted via cross-validation/sandbox reproduction.
"""
from __future__ import annotations

from memory.base import BaseMemory, Provenance


class SemanticMemory(BaseMemory):
    memory_type = "semantic"

    def ingest_external(self, *, key: str, content: dict, source: str, trust: float):
        # Untrusted by default: verified=False -> excluded from established() until promoted.
        return self.add(key=key, content=content, confidence=min(trust, 0.6),
                        provenance=Provenance(source, trust=trust), verified=False)
