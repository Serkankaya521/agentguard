"""Strategic memory: architecture-specific attack effectiveness."""
from __future__ import annotations

from memory.base import BaseMemory, Provenance


class StrategicMemory(BaseMemory):
    memory_type = "strategic"

    def record_effectiveness(self, *, architecture: str, technique: str, score: float,
                             tenant_id=None):
        return self.add(tenant_id=tenant_id, key=f"{architecture}:{technique}",
                        content={"architecture": architecture, "technique": technique,
                                 "effectiveness": float(score)},
                        confidence=0.7, provenance=Provenance("aegis", trust=0.9), verified=True)

    def best_for(self, architecture: str, tenant_id=None):
        recs = [r for r in self.established(tenant_id) if r.content.get("architecture") == architecture]
        return sorted(recs, key=lambda r: r.content.get("effectiveness", 0.0), reverse=True)
