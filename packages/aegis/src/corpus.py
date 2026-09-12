"""Adversarial corpus management (task plan 42).

De-duplicated, provenance-tracked corpus with bounded retention. Heuristic
candidates are quarantined; controlled promotion into the regression corpus
requires observed evidence (not a heuristic score).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional

from serialization import content_hash  # packages/contracts/src


@dataclass(frozen=True)
class CorpusEntry:
    entry_id: str
    fingerprint: str
    content: dict
    provenance: str
    label: str = "candidate"     # candidate | confirmed
    evidence_backed: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AdversarialCorpus:
    def __init__(self, max_size: int = 100_000) -> None:
        self._max = max_size
        self._by_fp: dict[str, CorpusEntry] = {}
        self._order: list[str] = []

    def add(self, *, content: dict, provenance: str, evidence_backed: bool = False) -> CorpusEntry:
        fp = content_hash(content)
        if fp in self._by_fp:               # de-duplication
            return self._by_fp[fp]
        entry = CorpusEntry(entry_id=f"c-{len(self._order)}", fingerprint=fp, content=content,
                            provenance=provenance, evidence_backed=evidence_backed)
        self._by_fp[fp] = entry
        self._order.append(fp)
        while len(self._order) > self._max:  # bounded retention
            self._by_fp.pop(self._order.pop(0), None)
        return entry

    def promote_to_regression(self, fingerprint: str, *, evidence_backed: bool) -> CorpusEntry:
        """Only evidence-backed (sandbox-observed) entries may be confirmed for the
        regression corpus. Heuristic-only promotion is refused."""
        entry = self._by_fp[fingerprint]
        if not evidence_backed:
            raise ValueError("regression promotion requires observed evidence, not heuristics")
        promoted = replace(entry, label="confirmed", evidence_backed=True)
        self._by_fp[fingerprint] = promoted
        return promoted

    def confirmed(self) -> list[CorpusEntry]:
        return [e for e in self._by_fp.values() if e.label == "confirmed"]

    def candidates(self) -> list[CorpusEntry]:
        return [e for e in self._by_fp.values() if e.label == "candidate"]
