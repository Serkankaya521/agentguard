"""Learning worker job (security-owned; off the hot path).

Runs hot learning (memory/strategy scores) and warm learning (detector/policy
proposals). Produces proposals only — never deploys (learning != privilege).
"""
from __future__ import annotations

from learning import hot_update, warm_propose_detector, warm_propose_policy  # packages/aegis/src


class LearningJob:
    def __init__(self, strategic_memory) -> None:
        self._strategic = strategic_memory

    def run_hot(self, observations: list[dict]) -> int:
        n = 0
        for o in observations:
            hot_update(self._strategic, architecture=o["architecture"],
                       technique=o["technique"], score=float(o["score"]),
                       tenant_id=o.get("tenant_id"))
            n += 1
        return n

    def run_warm(self, detector_signals: list[dict], policy_changes: list[dict]) -> list:
        proposals = [warm_propose_detector(pattern_label=s.get("label", "unknown"),
                                           sample_signals=s.get("samples", []))
                     for s in detector_signals]
        proposals += [warm_propose_policy(change=c) for c in policy_changes]
        return proposals
