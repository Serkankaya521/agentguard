"""Learning tiers (master arch 9; AGENTS.md #8).

hot  -> updates memory/strategy scores only; never model weights or production policy
warm -> produces detector/policy/attack-template PROPOSALS (never deploys)
cold -> requires curated dataset + poisoning check + dedup + offline eval + human
        approval + versioned artifact (governed via GovernancePipeline)
"""
from __future__ import annotations

import uuid
from typing import Optional

from governance import Proposal


class PrivilegeEscalationAttempt(RuntimeError):
    pass


def hot_update(strategic_memory, *, architecture: str, technique: str, score: float,
               tenant_id: Optional[str] = None):
    """Hot learning: memory/strategy score only. Cannot deploy or change privilege."""
    return strategic_memory.record_effectiveness(
        architecture=architecture, technique=technique, score=score, tenant_id=tenant_id)


def warm_propose_detector(*, pattern_label: str, sample_signals: list) -> Proposal:
    """Warm learning: a detector PROPOSAL. Enters governance; never auto-deploys."""
    return Proposal(proposal_id=f"prop-{uuid.uuid4()}", kind="detector",
                    content={"pattern_label": pattern_label, "samples": len(sample_signals)})


def warm_propose_policy(*, change: dict) -> Proposal:
    return Proposal(proposal_id=f"prop-{uuid.uuid4()}", kind="policy", content={"change": change})


def cold_requirements() -> dict:
    """Cold learning gate requirements (enforced by the governance lifecycle)."""
    return {"curated_dataset": True, "poisoning_check": True, "deduplication": True,
            "offline_evaluation": True, "human_approval": True, "versioned_artifact": True}
