"""Threat research ingestion + knowledge promotion (task plan 36, 37; master arch 23).

External threat intel is untrusted input. It is ingested QUARANTINED with a source
trust score, and only promoted to established semantic knowledge after trust +
cross-validation + sandbox reproduction + human verification. This resists
knowledge poisoning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from memory.base import Provenance

# Base trust per source class (0..1). Unknown sources are low-trust.
SOURCE_TRUST = {
    "cve": 0.8, "cwe": 0.8, "mitre": 0.85, "owasp": 0.8,
    "vendor_advisory": 0.6, "research": 0.5, "blog": 0.3, "unknown": 0.2,
}
TRUST_THRESHOLD = 0.5
MIN_CORROBORATION = 2


@dataclass(frozen=True)
class ThreatItem:
    item_id: str
    source: str
    source_type: str
    content: dict
    raw_trust: Optional[float] = None


@dataclass(frozen=True)
class PromotionDecision:
    promoted: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


class ThreatResearchIngestion:
    def __init__(self, semantic_memory) -> None:
        self._sem = semantic_memory

    def score_trust(self, item: ThreatItem) -> float:
        base = SOURCE_TRUST.get(item.source_type, SOURCE_TRUST["unknown"])
        return round(base if item.raw_trust is None else min(base, item.raw_trust), 4)

    def ingest(self, item: ThreatItem):
        """Store quarantined (unverified) in semantic memory."""
        return self._sem.ingest_external(
            key=item.item_id, content={**item.content, "source": item.source,
                                       "source_type": item.source_type},
            source=item.source, trust=self.score_trust(item))

    def promote(self, item: ThreatItem, record_id: str, *, corroborating_sources: int,
                sandbox_reproduce: Callable[[ThreatItem], bool], verifier: str
                ) -> PromotionDecision:
        """Promote to established knowledge only if ALL gates pass."""
        reasons = []
        if self.score_trust(item) < TRUST_THRESHOLD:
            reasons.append("source_trust_below_threshold")
        if corroborating_sources < MIN_CORROBORATION:
            reasons.append("insufficient_cross_validation")
        if not sandbox_reproduce(item):
            reasons.append("sandbox_reproduction_failed")
        if not verifier:
            reasons.append("human_verifier_required")
        if reasons:
            return PromotionDecision(False, tuple(reasons))
        self._sem.promote(record_id, verifier=verifier)
        return PromotionDecision(True, ("promoted",))
