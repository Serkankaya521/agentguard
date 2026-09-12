"""Remediation Regression Engine (task plan 23, 29).

Every RESOLVED_VERIFIED finding becomes a permanent regression case (fingerprinted
via Vulnerability DNA), replaying the original exploit + amplified variants + the
attack chain. On recurrence a finding is REOPENED, not recreated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

import vulnerability_dna as vdna
from enums import FindingState, RedTeamReason

SIMILARITY_THRESHOLD = 0.8


@dataclass(frozen=True)
class RegressionCase:
    case_id: str
    finding_id: str
    tenant_id: str
    fingerprint: str
    payloads: tuple[str, ...]
    dna: vdna.VulnerabilityDNA


@dataclass(frozen=True)
class RegressionResult:
    passed: bool
    reason: RedTeamReason
    failing_payloads: tuple[str, ...] = field(default_factory=tuple)


class RegressionEngine:
    def __init__(self) -> None:
        self._cases: dict[str, RegressionCase] = {}

    def register(self, finding: dict, *, amplified: Optional[list] = None,
                 chain: Optional[list] = None) -> RegressionCase:
        if finding.get("state") not in (FindingState.RESOLVED_VERIFIED.value,
                                        FindingState.RESOLVED_VERIFIED):
            raise ValueError("only RESOLVED_VERIFIED findings become regression cases")
        dna = vdna.from_finding(finding)
        payloads = tuple(list(finding.get("successful_mutations", []))
                         + list(amplified or []) + list(chain or []))
        case = RegressionCase(
            case_id=f"reg-{finding['finding_id']}", finding_id=finding["finding_id"],
            tenant_id=finding.get("tenant_id", "unknown"), fingerprint=dna.fingerprint(),
            payloads=payloads or ("<original-exploit>",), dna=dna)
        self._cases[case.case_id] = case
        return case

    def replay(self, case: RegressionCase, defense: Callable[[str], bool]) -> RegressionResult:
        """defense(payload) -> True if the attack is blocked. Any un-blocked payload
        means the weakness returned -> REOPENED."""
        failing = tuple(p for p in case.payloads if not defense(p))
        if failing:
            return RegressionResult(False, RedTeamReason.REGRESSION_REOPENED, failing)
        return RegressionResult(True, RedTeamReason.REGRESSION_PASS)

    def match(self, finding: dict) -> Optional[RegressionCase]:
        """If a new finding matches an existing case, REOPEN it instead of creating
        an unrelated record (task plan 23)."""
        dna = vdna.from_finding(finding)
        best, best_sim = None, 0.0
        for case in self._cases.values():
            sim = vdna.similarity(dna, case.dna)
            if sim > best_sim:
                best, best_sim = case, sim
        return best if best_sim >= SIMILARITY_THRESHOLD else None
