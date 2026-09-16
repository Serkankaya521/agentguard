"""Evidence capture + validation.

A model statement alone is NOT sufficient evidence of a successful attack
(AGENTS.md #7). Evidence is tenant-scoped, integrity-protected, prefers
references/hashes over raw payloads, and keeps blocked vs executed distinct.

Note: the validator lives here (not in validation.py) because a flat-layout
top-level `validation` module would overlap with packages/contracts - a packaging
item tracked for Developer B.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import integrity
from serialization import to_jsonable  # packages/contracts/src
from validation import validate  # packages/contracts/src (deterministic: contracts wins name)

OBSERVED_KINDS = frozenset({
    "deterministic_state", "tool_output", "resource_mutation", "hash",
    "network_event", "telemetry", "sandbox_observation", "policy_trace", "approval_record",
})
SUCCESS_KINDS = frozenset({"deterministic_state", "resource_mutation", "network_event"})


@dataclass(frozen=True)
class EvidenceSource:
    kind: str
    ref: str
    summary: dict = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    tenant_id: str
    event_id: str
    action_state: str
    sources: tuple[EvidenceSource, ...]
    integrity_hash: str
    created_at: str
    trace_id: Optional[str] = None
    prev_hash: Optional[str] = None
    signature: Optional[str] = None
    schema_version: str = "1.0.0"

    def to_dict(self) -> dict:
        return to_jsonable(self)


@dataclass(frozen=True)
class EvidenceValidationResult:
    integrity_ok: bool
    evidence_backed: bool
    supports_success: bool
    reasons: tuple[str, ...]


class EvidenceCapture:
    def __init__(self, key: Optional[object] = None) -> None:
        self._key = key

    def capture(self, *, tenant_id: str, event_id: str, action_state: str,
                sources: list[EvidenceSource], trace_id: Optional[str] = None,
                prev_hash: Optional[str] = None) -> EvidenceRecord:
        base = {
            "schema_version": "1.0.0",
            "evidence_id": f"ev-{uuid.uuid4()}",
            "tenant_id": tenant_id,
            "event_id": event_id,
            "trace_id": trace_id,
            "action_state": action_state,
            "sources": [to_jsonable(s) for s in sources],
            "prev_hash": prev_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        base["integrity_hash"] = integrity.content_hash(base)
        base["signature"] = integrity.sign(base, self._key)
        return EvidenceRecord(
            evidence_id=base["evidence_id"], tenant_id=tenant_id, event_id=event_id,
            action_state=action_state, sources=tuple(sources),
            integrity_hash=base["integrity_hash"], created_at=base["created_at"],
            trace_id=trace_id, prev_hash=prev_hash, signature=base["signature"])


class EvidenceValidator:
    def __init__(self, key: Optional[object] = None) -> None:
        self._key = key

    def validate(self, record: EvidenceRecord) -> EvidenceValidationResult:
        data = record.to_dict()
        reasons: list[str] = []

        if validate(data, "evidence"):
            return EvidenceValidationResult(False, False, False, ("schema_invalid",))

        integrity_ok, ireason = integrity.verify(data, self._key)
        if not integrity_ok:
            return EvidenceValidationResult(False, False, False, (ireason,))

        kinds = {s.kind for s in record.sources}
        has_observed = bool(kinds & OBSERVED_KINDS)
        model_only = kinds == {"model_claim"}
        if model_only:
            reasons.append("model_claim_only_not_sufficient")
        evidence_backed = has_observed and not model_only

        # A successful executed attack requires an observed state/resource/network change.
        supports_success = (
            record.action_state == "executed" and bool(kinds & SUCCESS_KINDS))
        if record.action_state != "executed":
            reasons.append(f"action_state_{record.action_state}")  # blocked != executed

        return EvidenceValidationResult(True, evidence_backed, supports_success, tuple(reasons))
