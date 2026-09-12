"""Self-improvement governance (master arch 16; AGENTS.md #10).

AEGIS may PROPOSE detectors/policies/strategies; it may never self-deploy a
security-affecting change. Production requires the full ordered lifecycle with a
human approval and a signed artifact, and every version supports rollback.

    Proposal -> Unit Tests -> Historical Corpus -> False-positive -> Performance
    -> Sandbox -> Shadow -> Canary -> Human Approval -> Signed Artifact -> Production
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field, replace
from typing import Optional

from serialization import canonical_json  # packages/contracts/src

STAGES = (
    "PROPOSAL", "UNIT_TESTS", "HISTORICAL_CORPUS", "FALSE_POSITIVE", "PERFORMANCE",
    "SANDBOX", "SHADOW", "CANARY", "HUMAN_APPROVAL", "SIGNED_ARTIFACT", "PRODUCTION",
)
_AUTOMATED = STAGES[1:8]          # UNIT_TESTS..CANARY (AEGIS may drive these)
_HUMAN_APPROVAL = "HUMAN_APPROVAL"
_SIGNED = "SIGNED_ARTIFACT"
_PRODUCTION = "PRODUCTION"


class GovernanceViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    kind: str                       # detector | policy | strategy | attack_template
    content: dict
    stage: str = "PROPOSAL"
    passed_gates: tuple = field(default_factory=tuple)
    approver: Optional[str] = None
    signature: Optional[str] = None
    created_by: str = "aegis"

    def _idx(self) -> int:
        return STAGES.index(self.stage)


class GovernancePipeline:
    def __init__(self, *, signing_key: Optional[object] = None) -> None:
        self._key = signing_key

    def pass_gate(self, proposal: Proposal, gate: str, *, passed: bool) -> Proposal:
        """Advance one automated gate. No skipping; a failed gate does not advance."""
        if gate not in _AUTOMATED:
            raise GovernanceViolation(f"{gate} is not an automated gate")
        expected = STAGES[proposal._idx() + 1]
        if gate != expected:
            raise GovernanceViolation(f"out-of-order gate: expected {expected}, got {gate}")
        if not passed:
            return proposal  # stays; must be re-run
        return replace(proposal, stage=gate, passed_gates=proposal.passed_gates + (gate,))

    def approve(self, proposal: Proposal, *, approver: str, is_human: bool = True) -> Proposal:
        if not is_human:
            raise GovernanceViolation("only a human can approve (learning != privilege)")
        if not approver:
            raise GovernanceViolation("approver required")
        if proposal.stage != "CANARY":
            raise GovernanceViolation("approval requires all automated gates first")
        return replace(proposal, stage=_HUMAN_APPROVAL, approver=approver,
                       passed_gates=proposal.passed_gates + (_HUMAN_APPROVAL,))

    def sign(self, proposal: Proposal) -> Proposal:
        if proposal.stage != _HUMAN_APPROVAL or not proposal.approver:
            raise GovernanceViolation("cannot sign before human approval")
        payload = canonical_json({"id": proposal.proposal_id, "kind": proposal.kind,
                                  "content": proposal.content, "approver": proposal.approver})
        kb = (self._key if isinstance(self._key, bytes)
              else str(self._key or "unsigned").encode("utf-8"))
        sig = "hmac-sha256:" + hmac.new(kb, payload.encode(), hashlib.sha256).hexdigest()
        return replace(proposal, stage=_SIGNED, signature=sig,
                       passed_gates=proposal.passed_gates + (_SIGNED,))

    def promote(self, proposal: Proposal) -> Proposal:
        if proposal.stage != _SIGNED or not proposal.signature:
            raise GovernanceViolation("production requires a signed, human-approved artifact")
        return replace(proposal, stage=_PRODUCTION,
                       passed_gates=proposal.passed_gates + (_PRODUCTION,))

    def aegis_attempt_deploy(self, proposal: Proposal) -> Proposal:
        """AEGIS trying to deploy on its own always fails."""
        raise GovernanceViolation("AEGIS cannot deploy a security-affecting change")


class ProductionRegistry:
    """Holds the active artifact per kind with rollback to the previous one."""

    def __init__(self) -> None:
        self._active: dict[str, Proposal] = {}
        self._history: dict[str, list[Proposal]] = {}

    def deploy(self, proposal: Proposal) -> None:
        if proposal.stage != _PRODUCTION:
            raise GovernanceViolation("only PRODUCTION artifacts may be deployed")
        cur = self._active.get(proposal.kind)
        if cur is not None:
            self._history.setdefault(proposal.kind, []).append(cur)
        self._active[proposal.kind] = proposal

    def active(self, kind: str) -> Optional[Proposal]:
        return self._active.get(kind)

    def rollback(self, kind: str) -> Optional[Proposal]:
        hist = self._history.get(kind, [])
        if not hist:
            return self._active.get(kind)
        self._active[kind] = hist.pop()
        return self._active[kind]
