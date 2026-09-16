"""Tenant/identity/environment context validation.

Core Security never guesses tenant context (AGENTS.md #5). A missing or invalid
critical field yields explicit reason codes; the pipeline routes such events to a
safe decision rather than fabricating a context.
"""
from __future__ import annotations

from enums import ReasonCode
from tenant import TenantContext

# Fields that must be present for any runtime decision.
_CRITICAL = (
    ("tenant_id", ReasonCode.CONTEXT_MISSING_TENANT),
    ("workspace_id", ReasonCode.CONTEXT_MISSING_WORKSPACE),
    ("environment_id", ReasonCode.CONTEXT_MISSING_ENVIRONMENT),
    ("identity_id", ReasonCode.CONTEXT_MISSING_IDENTITY),
)


def validate_context(tenant: TenantContext) -> list[ReasonCode]:
    """Return a list of failure reason codes; empty means the context is valid."""
    reasons: list[ReasonCode] = []
    for attr, code in _CRITICAL:
        if not getattr(tenant, attr, ""):
            reasons.append(code)
    return reasons
