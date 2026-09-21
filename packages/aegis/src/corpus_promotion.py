"""Promotion policy: response-aware campaign output -> corpus + vulnerability DNA.

Connects the response-aware engine to the AEGIS knowledge with one governed rule:
only an *observed* evidence level (a target-side canary, a sandbox observation, a
resource/network/state change) promotes a candidate into the regression corpus and
the vulnerability-DNA index. A heuristic fitness score never promotes, no matter how
high — it only ever quarantines a candidate for review (AGENTS.md #7, #9). This is
defence in depth over AdversarialCorpus.promote_to_regression: promotion is refused
unless the evidence level is one actually observed at the target, not merely a caller
passing evidence_backed=True.

A DNA similarity match prioritises testing; it is never itself a confirmation
(master arch 21).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from corpus import AdversarialCorpus, CorpusEntry
from vulnerability_dna import VulnerabilityDNA, from_finding, similarity

# Evidence levels that represent something observed at the target / in a sandbox.
OBSERVED_EVIDENCE_LEVELS = frozenset({
    "target_canary", "sandbox_observation", "resource_mutation",
    "network_event", "deterministic_state",
})
# Explicitly non-promotable: a model/heuristic signal alone.
HEURISTIC_EVIDENCE_LEVELS = frozenset({"heuristic", "response_heuristic", "model_claim"})


@dataclass(frozen=True)
class PromotionOutcome:
    fingerprint: str
    promoted: bool
    reason: str
    dna_fingerprint: str = ""


@dataclass(frozen=True)
class PromotionResult:
    promoted: tuple[str, ...] = field(default_factory=tuple)
    quarantined: tuple[str, ...] = field(default_factory=tuple)
    dna_fingerprints: tuple[str, ...] = field(default_factory=tuple)


class VulnerabilityDNAIndex:
    """De-duplicated DNA registry with similarity lookup for test prioritisation."""

    def __init__(self, *, match_threshold: float = 0.5) -> None:
        self._threshold = match_threshold
        self._by_fp: dict[str, VulnerabilityDNA] = {}

    def register(self, dna: VulnerabilityDNA) -> str:
        fp = dna.fingerprint()
        self._by_fp.setdefault(fp, dna)
        return fp

    def known(self) -> list[str]:
        return list(self._by_fp)

    def matches(self, dna: VulnerabilityDNA, *, threshold: float | None = None):
        """Return (fingerprint, score) above threshold, best first. Prioritisation
        only — never a confirmation."""
        cutoff = self._threshold if threshold is None else threshold
        scored = [(fp, similarity(dna, known)) for fp, known in self._by_fp.items()]
        return sorted([(fp, s) for fp, s in scored if s >= cutoff],
                      key=lambda x: x[1], reverse=True)


class CorpusPromotionPolicy:
    def __init__(self, corpus: AdversarialCorpus | None = None,
                 dna_index: VulnerabilityDNAIndex | None = None) -> None:
        self.corpus = corpus or AdversarialCorpus()
        self.dna_index = dna_index or VulnerabilityDNAIndex()

    @staticmethod
    def _is_observed(evidence_level: str) -> bool:
        return evidence_level in OBSERVED_EVIDENCE_LEVELS

    def ingest_candidate(self, *, content: dict, evidence_level: str,
                         finding: dict | None = None,
                         provenance: str = "response_aware_campaign") -> PromotionOutcome:
        """Add one candidate; promote it iff its evidence level was observed."""
        observed = self._is_observed(evidence_level)
        entry: CorpusEntry = self.corpus.add(content=content, provenance=provenance,
                                             evidence_backed=observed)
        if not observed:
            return PromotionOutcome(entry.fingerprint, False,
                                    f"quarantined_{evidence_level or 'unspecified'}")
        # Observed -> confirm in the corpus and index the DNA of the finding.
        self.corpus.promote_to_regression(entry.fingerprint, evidence_backed=True)
        dna_fp = ""
        if finding is not None:
            dna_fp = self.dna_index.register(from_finding({**finding, "evidence_level": evidence_level}))
        return PromotionOutcome(entry.fingerprint, True, f"promoted_{evidence_level}", dna_fp)

    def ingest_campaign(self, candidates) -> PromotionResult:
        """Ingest response-aware candidates. Each item: {content, evidence_level,
        finding?}. Only observed-evidence candidates are promoted."""
        promoted, quarantined, dnas = [], [], []
        for cand in candidates:
            outcome = self.ingest_candidate(
                content=cand["content"], evidence_level=cand.get("evidence_level", ""),
                finding=cand.get("finding"),
                provenance=cand.get("provenance", "response_aware_campaign"))
            (promoted if outcome.promoted else quarantined).append(outcome.fingerprint)
            if outcome.dna_fingerprint:
                dnas.append(outcome.dna_fingerprint)
        return PromotionResult(tuple(promoted), tuple(quarantined), tuple(dict.fromkeys(dnas)))

    def prioritized_matches(self, finding: dict, *, threshold: float | None = None):
        """Known DNA similar to a new candidate finding, to prioritise testing."""
        return self.dna_index.matches(from_finding(finding), threshold=threshold)


def campaign_candidates(observations, confirmed_findings=()):
    """Map response-aware output to policy candidates.

    `observations` are CampaignSummary.capture_result().observations (each carries an
    `evidence_level`, defaulting heuristic). `confirmed_findings` are the target-canary
    findings the durable executor promoted (evidence_level target_canary). Only the
    latter carry finding DNA and clear the promotion bar.
    """
    for obs in observations:
        yield {"content": {k: obs.get(k) for k in ("technique", "generation", "response_sha256")},
               "evidence_level": obs.get("evidence_level", "response_heuristic"),
               "finding": None}
    for finding in confirmed_findings:
        yield {"content": {"regression_fingerprint": finding.get("regression_fingerprint"),
                           "successful_mutations": finding.get("successful_mutations")},
               "evidence_level": finding.get("evidence_level", "target_canary"),
               "finding": finding}
