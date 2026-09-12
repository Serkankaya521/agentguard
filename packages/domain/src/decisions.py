"""PolicyDecision (PDP output) and RuntimeDecision (final, with metadata)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from enums import ActionState, CacheSource, Decision, FailMode, ReasonCode

SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class PolicyDecision:
    """Produced by the PDP. Enforcement happens elsewhere (PEP)."""
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    risk_score: float
    fail_mode: FailMode
    policy_version: str
    policy_hash: str
    capability_id: Optional[str] = None
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class RuntimeDecision:
    """Final decision emitted by the runtime gateway, with correlation and
    performance metadata. Must never carry PII or secrets."""
    decision_id: str
    tenant_id: str
    event_id: str
    trace_id: str
    policy_version: str
    policy_hash: str
    runtime_version: str
    risk_score: float
    reason_codes: tuple[ReasonCode, ...]
    cache_source: CacheSource
    latency_us: int
    trajectory_version: int
    decision: Decision
    fail_mode: FailMode
    action_state: ActionState
    capability_id: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
