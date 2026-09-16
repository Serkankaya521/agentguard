"""Runtime-side evidence capture (Developer A: capture/validation/integrity).

Builds a tenant-scoped, integrity-protected EvidenceRecord from a runtime
decision. Uses references/hashes, never raw payloads; keeps blocked vs executed
distinct. Blob storage/viewer are Developer B.
"""
from __future__ import annotations

from typing import Optional

from capture import EvidenceCapture, EvidenceSource  # packages/evidence/src


class RuntimeEvidenceCapture:
    def __init__(self, key: Optional[object] = None) -> None:
        self._cap = EvidenceCapture(key)

    def from_decision(self, event, runtime_decision, *, prev_hash: Optional[str] = None):
        sources = [
            EvidenceSource("policy_trace", runtime_decision.policy_hash,
                           {"decision": runtime_decision.decision.value,
                            "reason_codes": [r.value for r in runtime_decision.reason_codes]}),
            EvidenceSource("deterministic_state", runtime_decision.decision_id,
                           {"action_state": runtime_decision.action_state.value,
                            "risk_score": runtime_decision.risk_score}),
            EvidenceSource("hash", getattr(event, "payload_hash", "sha256:-")),
        ]
        return self._cap.capture(
            tenant_id=runtime_decision.tenant_id, event_id=runtime_decision.event_id,
            action_state=runtime_decision.action_state.value, sources=sources,
            trace_id=runtime_decision.trace_id, prev_hash=prev_hash)
