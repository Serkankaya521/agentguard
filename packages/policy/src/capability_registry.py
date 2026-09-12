"""Tool Capability Registry enforcement.

Boundary law (AGENTS.md #1, #2; master arch 6): tool authority comes from the
registry, never from the tool name. Unknown capabilities in critical contexts
are not silently trusted. Developer B owns registry management/persistence; this
module owns lookup + enforcement semantics on the hot path.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from enums import ApprovalMode, Sensitivity, SideEffect

SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class ToolCapability:
    tool_id: str
    capabilities: tuple[str, ...]
    side_effect: SideEffect
    sensitivity: Sensitivity
    approval_mode: ApprovalMode
    version: str
    resource_patterns: tuple[str, ...] = field(default_factory=tuple)
    data_classes: tuple[str, ...] = field(default_factory=tuple)
    environment: str = "*"
    fail_open_allowed: bool = False
    schema_version: str = SCHEMA_VERSION

    @staticmethod
    def from_dict(data: dict) -> "ToolCapability":
        return ToolCapability(
            tool_id=str(data["tool_id"]),
            capabilities=tuple(str(c) for c in data.get("capabilities", ())),
            side_effect=SideEffect(str(data.get("side_effect", "none"))),
            sensitivity=Sensitivity(str(data.get("sensitivity", "low"))),
            approval_mode=ApprovalMode(str(data.get("approval_mode", "never"))),
            version=str(data.get("version", "0")),
            resource_patterns=tuple(str(p) for p in data.get("resource_patterns", ())),
            data_classes=tuple(str(d) for d in data.get("data_classes", ())),
            environment=str(data.get("environment", "*")),
            fail_open_allowed=bool(data.get("fail_open_allowed", False)),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
        )

    def resource_in_scope(self, resource_scope: Optional[str]) -> bool:
        """A resource is in scope only if it matches an allowed pattern.

        No patterns declared -> the tool is not scoped to a resource, so any
        resource request is out of scope (fail-closed default)."""
        if resource_scope is None:
            return True  # no resource targeted by this call
        if not self.resource_patterns:
            return False
        return any(fnmatch.fnmatchcase(resource_scope, p) for p in self.resource_patterns)


@dataclass(frozen=True)
class CapabilityResolution:
    """Result of resolving a tool call against the registry."""
    known: bool
    record: Optional[ToolCapability]
    capability_id: Optional[str]
    mismatch: bool  # declared capability not among the tool's authoritative set


class CapabilityRegistry:
    """In-memory, hot-path registry client. L2/L3-backed loading and
    invalidation are wired in later sprints; this holds the enforcement
    semantics and lookup contract."""

    def __init__(self, records: Optional[dict[str, ToolCapability]] = None) -> None:
        self._by_tool: dict[str, ToolCapability] = dict(records or {})

    def register(self, record: ToolCapability) -> None:
        self._by_tool[record.tool_id] = record

    def resolve(self, tool_id: str, declared_capability_id: Optional[str]) -> CapabilityResolution:
        record = self._by_tool.get(tool_id)
        if record is None:
            return CapabilityResolution(known=False, record=None, capability_id=None, mismatch=False)
        if declared_capability_id is not None and declared_capability_id not in record.capabilities:
            # Caller claims a capability the tool is not authorized for: possible
            # metadata/capability spoofing.
            return CapabilityResolution(
                known=True, record=record,
                capability_id=record.capabilities[0] if record.capabilities else None,
                mismatch=True,
            )
        capability_id = declared_capability_id or (record.capabilities[0] if record.capabilities else None)
        return CapabilityResolution(known=True, record=record, capability_id=capability_id, mismatch=False)
