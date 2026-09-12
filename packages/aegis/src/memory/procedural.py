"""Procedural memory: which testing strategies apply to which problems."""
from __future__ import annotations

from memory.base import BaseMemory, Provenance


class ProceduralMemory(BaseMemory):
    memory_type = "procedural"

    def record_strategy(self, *, key: str, steps: list, confidence: float = 0.7,
                        source: str = "internal", tenant_id=None, verified: bool = True):
        return self.add(tenant_id=tenant_id, key=key, content={"steps": list(steps)},
                        confidence=confidence, provenance=Provenance(source, trust=0.9),
                        verified=verified)
