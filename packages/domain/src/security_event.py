"""SecurityEvent: the normalized inbound event every source converges to."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from enums import ActionState, EventSource
from tenant import TenantContext

SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    trace_id: str
    occurred_at: str
    source: EventSource
    action_state: ActionState
    tenant: TenantContext
    tool_id: str
    payload_hash: str
    trajectory_id: Optional[str] = None
    declared_capability_id: Optional[str] = None
    resource_scope: Optional[str] = None
    arguments: dict = field(default_factory=dict)
    payload_ref: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
