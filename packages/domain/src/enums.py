"""Shared enumerations for AgentGuard core-security domain.

Values here are the single source of truth for string constants used across
schemas and code. Every value matches the corresponding JSON Schema `enum`.
"""
from __future__ import annotations

from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    SANDBOX = "SANDBOX"
    REDACT = "REDACT"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    ASYNC_DEEP_ANALYSIS = "ASYNC_DEEP_ANALYSIS"


class ActionState(str, Enum):
    """A blocked attempt and an executed action are different states (AGENTS.md #8)."""
    PROPOSED = "proposed"
    BLOCKED = "blocked"
    APPROVED = "approved"
    EXECUTED = "executed"


class FailMode(str, Enum):
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class EventSource(str, Enum):
    HTTP = "http"
    MCP = "mcp"
    SDK = "sdk"
    AGENT_FRAMEWORK = "agent_framework"
    TOOL_WRAPPER = "tool_wrapper"
    MESSAGE_INTEGRATION = "message_integration"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class IdentityType(str, Enum):
    USER = "user"
    SERVICE = "service"
    AGENT = "agent"


class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SideEffect(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    NETWORK = "network"
    EXECUTE = "execute"
    ADMIN = "admin"


class ApprovalMode(str, Enum):
    NEVER = "never"
    CONDITIONAL = "conditional"
    ALWAYS = "always"


class CacheSource(str, Enum):
    L1 = "l1"
    L2 = "l2"
    L3 = "l3"
    COMPUTED = "computed"
    NONE = "none"


class ReasonCode(str, Enum):
    """Stable, explainable reason codes. Never change a value once shipped."""
    # context
    CONTEXT_VALID = "CONTEXT_VALID"
    CONTEXT_MISSING_TENANT = "CONTEXT_MISSING_TENANT"
    CONTEXT_MISSING_WORKSPACE = "CONTEXT_MISSING_WORKSPACE"
    CONTEXT_MISSING_ENVIRONMENT = "CONTEXT_MISSING_ENVIRONMENT"
    CONTEXT_MISSING_IDENTITY = "CONTEXT_MISSING_IDENTITY"
    CONTEXT_INVALID_ENUM = "CONTEXT_INVALID_ENUM"
    # normalization
    NORMALIZATION_SCHEMA_INVALID = "NORMALIZATION_SCHEMA_INVALID"
    NORMALIZATION_MALFORMED_INPUT = "NORMALIZATION_MALFORMED_INPUT"
    PAYLOAD_TRUNCATED = "PAYLOAD_TRUNCATED"
    # capability
    CAPABILITY_KNOWN = "CAPABILITY_KNOWN"
    CAPABILITY_UNKNOWN = "CAPABILITY_UNKNOWN"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    CAPABILITY_STALE = "CAPABILITY_STALE"
    RESOURCE_SCOPE_VIOLATION = "RESOURCE_SCOPE_VIOLATION"
    # decision
    ALLOWED_LOW_RISK = "ALLOWED_LOW_RISK"
    BLOCKED_HIGH_SENSITIVITY = "BLOCKED_HIGH_SENSITIVITY"
    BLOCKED_DESTRUCTIVE_SIDE_EFFECT = "BLOCKED_DESTRUCTIVE_SIDE_EFFECT"
    APPROVAL_REQUIRED_ALWAYS = "APPROVAL_REQUIRED_ALWAYS"
    APPROVAL_REQUIRED_CONDITIONAL = "APPROVAL_REQUIRED_CONDITIONAL"
    APPROVAL_REQUIRED_UNKNOWN_CAPABILITY = "APPROVAL_REQUIRED_UNKNOWN_CAPABILITY"
    BLOCKED_UNKNOWN_CAPABILITY_PROD = "BLOCKED_UNKNOWN_CAPABILITY_PROD"
    # fail mode
    FAIL_CLOSED_DEPENDENCY = "FAIL_CLOSED_DEPENDENCY"
    FAIL_OPEN_POLICY = "FAIL_OPEN_POLICY"
    # provenance
    BUILTIN_RULESET = "BUILTIN_RULESET"
