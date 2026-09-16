"""Finding entity with lifecycle transitions (task plan 23)."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional

from enums import FindingState

SCHEMA_VERSION = "1.0.0"

# Allowed lifecycle transitions.
_TRANSITIONS = {
    FindingState.SUSPECTED: {FindingState.VALIDATING, FindingState.FALSE_POSITIVE},
    FindingState.VALIDATING: {FindingState.CONFIRMED, FindingState.FALSE_POSITIVE},
    FindingState.CONFIRMED: {FindingState.FIX_PROPOSED, FindingState.FALSE_POSITIVE},
    FindingState.FIX_PROPOSED: {FindingState.RETESTING},
    FindingState.RETESTING: {FindingState.RESOLVED_VERIFIED, FindingState.CONFIRMED},
    FindingState.RESOLVED_VERIFIED: {FindingState.REOPENED},
    FindingState.REOPENED: {FindingState.VALIDATING, FindingState.CONFIRMED},
    FindingState.FALSE_POSITIVE: set(),
}


class InvalidTransition(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    finding_id: str
    tenant_id: str
    state: FindingState
    root_cause: str
    affected_architecture: Optional[str] = None
    model_family: Optional[str] = None
    agent_type: Optional[str] = None
    tool_capability: Optional[str] = None
    permission_topology: Optional[str] = None
    mcp_topology: Optional[str] = None
    preconditions: tuple[str, ...] = field(default_factory=tuple)
    successful_mutations: tuple[str, ...] = field(default_factory=tuple)
    failed_mutations: tuple[str, ...] = field(default_factory=tuple)
    side_effects: tuple[str, ...] = field(default_factory=tuple)
    evidence_pattern: Optional[str] = None
    evidence_backed: bool = False
    remediation: Optional[str] = None
    regression_fingerprint: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def transition(self, to: FindingState) -> "Finding":
        if to not in _TRANSITIONS.get(self.state, set()):
            raise InvalidTransition(f"{self.state.value} -> {to.value}")
        return replace(self, state=to)
