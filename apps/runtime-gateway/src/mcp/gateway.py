"""MCP source adapter: normalize an MCP tool call into a SecurityEvent.

The runtime gateway accepts MCP traffic as one of its sources (master arch 6).
This maps an MCP tool-call message + validated tenant context into the raw shape
the normalizer consumes.
"""
from __future__ import annotations

from enums import EventSource
from normalization import NormalizationResult, normalize


def mcp_to_raw(message: dict, tenant: dict) -> dict:
    return {
        "event_id": message.get("id"),
        "trace_id": message.get("trace_id"),
        "tool_id": message.get("tool") or message.get("name", ""),
        "declared_capability_id": message.get("capability"),
        "resource_scope": message.get("resource"),
        "arguments": message.get("arguments") or message.get("params") or {},
        "tenant": tenant,
    }


class McpGateway:
    def handle(self, message: dict, tenant: dict) -> NormalizationResult:
        return normalize(mcp_to_raw(message, tenant), EventSource.MCP)
