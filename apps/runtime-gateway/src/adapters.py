"""Source adapters: converge every ingress shape onto one raw SecurityEvent dict.

Each agent surface (MCP JSON-RPC, an SDK call, an agent-framework step, a tool
wrapper, a chat/message integration) describes a proposed tool call differently.
An adapter is a pure, deterministic, bounded shape-mapper: framework-native payload
-> the raw dict `normalize()` consumes. Adapters confer no authority — they only
carry the *declared* capability through; the capability registry remains the sole
source of tool authority (AGENTS.md: authority from the capability registry, not
the tool name), and the schema + tenant validation in `normalize()` stays the trust
boundary. No network, no LLM, no I/O here (hot-path law).

`adapt(source, payload, tenant)` picks the adapter for the source and returns a
NormalizationResult, so an unrecognised or malformed payload becomes a
normalization error, never a crash and never a security finding.
"""
from __future__ import annotations

import json
from typing import Callable, Mapping, Optional

from enums import EventSource, ReasonCode
from normalization import NormalizationResult, normalize

# An adapter maps (payload, tenant) -> raw dict, or None if it cannot find a tool call.
Adapter = Callable[[Mapping, Mapping], Optional[dict]]

_MCP_TOOL_METHODS = {"tools/call", "tool/call", "call_tool"}


def _first(payload: Mapping, *keys: str):
    for key in keys:
        if payload.get(key) not in (None, ""):
            return payload[key]
    return None


def _as_arguments(value) -> Optional[dict]:
    """Accept a dict, or a JSON object string (OpenAI tool-call style). Else None."""
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _raw(*, tool_id, arguments, tenant, capability=None, resource=None, payload: Mapping) -> Optional[dict]:
    args = _as_arguments(arguments)
    if not tool_id or args is None:
        return None
    return {
        "event_id": _first(payload, "event_id", "id"),
        "trace_id": _first(payload, "trace_id", "traceId", "correlation_id"),
        "tool_id": str(tool_id),
        "declared_capability_id": capability,
        "resource_scope": resource,
        "arguments": args,
        "trajectory_id": _first(payload, "trajectory_id", "session_id", "thread_id"),
        "tenant": tenant,
    }


def mcp_adapter(payload: Mapping, tenant: Mapping) -> Optional[dict]:
    """MCP JSON-RPC `tools/call`, or the flat `{tool, arguments}` shape."""
    method = payload.get("method")
    if method is not None:
        if method not in _MCP_TOOL_METHODS:
            return None  # notifications, tools/list, etc. are not tool-call events
        params = payload.get("params") or {}
        if not isinstance(params, Mapping):
            return None
        return _raw(tool_id=_first(params, "name", "tool"),
                    arguments=params.get("arguments") or params.get("args"),
                    capability=params.get("capability"), resource=params.get("resource"),
                    tenant=tenant, payload={**payload, "id": payload.get("id")})
    return _raw(tool_id=_first(payload, "tool", "name"),
                arguments=_first(payload, "arguments", "params"),
                capability=payload.get("capability"), resource=payload.get("resource"),
                tenant=tenant, payload=payload)


def sdk_adapter(payload: Mapping, tenant: Mapping) -> Optional[dict]:
    """Direct SDK call: fields already close to the SecurityEvent shape."""
    return _raw(tool_id=_first(payload, "tool_id", "tool", "name"),
                arguments=_first(payload, "arguments", "args") or {},
                capability=_first(payload, "declared_capability_id", "capability"),
                resource=_first(payload, "resource_scope", "resource"),
                tenant=tenant, payload=payload)


def agent_framework_adapter(payload: Mapping, tenant: Mapping) -> Optional[dict]:
    """LangChain/LangGraph action (`{tool, tool_input}`) or an OpenAI tool call
    (`{function: {name, arguments}}` / `{type: 'function', ...}`)."""
    function = payload.get("function")
    if isinstance(function, Mapping):
        return _raw(tool_id=function.get("name"), arguments=function.get("arguments"),
                    capability=payload.get("capability"), resource=payload.get("resource"),
                    tenant=tenant, payload=payload)
    return _raw(tool_id=_first(payload, "tool", "action", "name"),
                arguments=_first(payload, "tool_input", "arguments", "action_input", "args") or {},
                capability=payload.get("capability"), resource=payload.get("resource"),
                tenant=tenant, payload=payload)


def tool_wrapper_adapter(payload: Mapping, tenant: Mapping) -> Optional[dict]:
    """A wrapped/decorated function call: `{name, args|kwargs}`."""
    return _raw(tool_id=_first(payload, "name", "function", "tool"),
                arguments=_first(payload, "kwargs", "arguments", "args") or {},
                capability=payload.get("capability"), resource=payload.get("resource"),
                tenant=tenant, payload=payload)


def message_integration_adapter(payload: Mapping, tenant: Mapping) -> Optional[dict]:
    """Chat/message surface: a slash-command style `{command, args}` maps to a tool."""
    return _raw(tool_id=_first(payload, "tool", "command", "intent"),
                arguments=_first(payload, "arguments", "args", "parameters") or {},
                capability=payload.get("capability"),
                resource=_first(payload, "resource", "channel"),
                tenant=tenant, payload=payload)


ADAPTERS: dict[EventSource, Adapter] = {
    EventSource.MCP: mcp_adapter,
    EventSource.SDK: sdk_adapter,
    EventSource.AGENT_FRAMEWORK: agent_framework_adapter,
    EventSource.TOOL_WRAPPER: tool_wrapper_adapter,
    EventSource.MESSAGE_INTEGRATION: message_integration_adapter,
}


def adapt(source, payload: object, tenant: Mapping) -> NormalizationResult:
    """Map a framework-native payload to a SecurityEvent via its source adapter."""
    try:
        event_source = source if isinstance(source, EventSource) else EventSource(str(source))
    except ValueError:
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])
    adapter = ADAPTERS.get(event_source)
    if adapter is None or not isinstance(payload, Mapping):
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])
    raw = adapter(payload, tenant)
    if raw is None:
        return NormalizationResult(None, [ReasonCode.NORMALIZATION_MALFORMED_INPUT])
    return normalize(raw, event_source)
