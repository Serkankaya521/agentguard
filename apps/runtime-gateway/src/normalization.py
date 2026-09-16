"""SecurityEvent normalization.

Every source (HTTP/MCP/SDK/framework/wrapper) converges to a schema-valid
SecurityEvent. Normalization/provider errors are returned as such - they are not
security findings (AGENTS.md #7, section 6 of the task plan). Missing critical
context makes the event schema-invalid and is rejected here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from config import MAX_INLINE_PAYLOAD_BYTES
from enums import ActionState, EventSource, ReasonCode
from security_event import SecurityEvent
from tenant import TenantContext

from serialization import canonical_json, content_hash  # packages/contracts/src
from validation import validate  # packages/contracts/src


class NormalizationResult:
    __slots__ = ("event", "errors")

    def __init__(self, event: Optional[SecurityEvent], errors: list[ReasonCode]):
        self.event = event
        self.errors = errors

    @property
    def ok(self) -> bool:
        return self.event is not None and not self.errors


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize(raw: object, source: object) -> NormalizationResult:
    if not isinstance(raw, dict):
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])

    # Source may be an EventSource or a raw string from the transport.
    try:
        event_source = source if isinstance(source, EventSource) else EventSource(str(source))
    except ValueError:
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])

    errors: list[ReasonCode] = []

    # Build tenant context. Invalid enums are a normalization error, not a finding.
    try:
        tenant = TenantContext.from_dict(raw.get("tenant") or {})
    except ValueError:
        return NormalizationResult(None, [ReasonCode.CONTEXT_INVALID_ENUM])

    # Bound the inline payload carried on the hot path.
    arguments = raw.get("arguments") or {}
    if not isinstance(arguments, dict):
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])
    payload_ref: Optional[str] = raw.get("payload_ref")
    canonical = canonical_json(arguments)
    payload_hash = content_hash(arguments)
    if len(canonical.encode("utf-8")) > MAX_INLINE_PAYLOAD_BYTES:
        payload_ref = payload_ref or payload_hash
        arguments = {}
        errors.append(ReasonCode.PAYLOAD_TRUNCATED)

    action_state = ActionState(str(raw.get("action_state", ActionState.PROPOSED.value)))

    event = SecurityEvent(
        event_id=str(raw.get("event_id") or uuid.uuid4()),
        trace_id=str(raw.get("trace_id") or uuid.uuid4()),
        occurred_at=str(raw.get("occurred_at") or _now_iso()),
        source=event_source,
        action_state=action_state,
        tenant=tenant,
        tool_id=str(raw.get("tool_id", "")),
        payload_hash=payload_hash,
        trajectory_id=(str(raw["trajectory_id"]) if raw.get("trajectory_id") else None),
        declared_capability_id=(str(raw["declared_capability_id"]) if raw.get("declared_capability_id") else None),
        resource_scope=(str(raw["resource_scope"]) if raw.get("resource_scope") else None),
        arguments=arguments,
        payload_ref=payload_ref,
    )

    # Validate the normalized event (incl. embedded tenant) against the schema.
    # Missing critical context makes this fail -> the event is rejected here.
    from serialization import to_jsonable  # local import to avoid cycles at top
    schema_errors = validate(to_jsonable(event), "security_event")
    if schema_errors:
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_SCHEMA_INVALID])

    return NormalizationResult(event, errors)
