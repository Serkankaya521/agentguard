"""MCP source adapter: normalize an MCP tool call into a SecurityEvent.

The runtime gateway accepts MCP traffic as one of its sources (master arch 6).
Shape-mapping now lives in the shared adapter layer (`adapters.mcp_adapter`), which
handles both JSON-RPC `tools/call` and the flat `{tool, arguments}` shape; this
class remains as the MCP entry point.
"""
from __future__ import annotations

from enums import EventSource, ReasonCode
from normalization import NormalizationResult, normalize
from adapters import mcp_adapter


def mcp_to_raw(message: dict, tenant: dict) -> dict:
    """Back-compat helper: raw dict for the flat MCP shape (may be None-valued)."""
    return mcp_adapter(message, tenant) or {"tenant": tenant, "tool_id": ""}


class McpGateway:
    def handle(self, message: dict, tenant: dict) -> NormalizationResult:
        raw = mcp_adapter(message, tenant)
        if raw is None:
            return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])
        return normalize(raw, EventSource.MCP)
