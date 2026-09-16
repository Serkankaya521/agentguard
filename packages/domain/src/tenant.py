"""TenantContext value object.

Boundary law (AGENTS.md #4, #5): every security event and decision carries an
explicit, validated tenant context. Core Security never guesses it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from enums import Environment, IdentityType

SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    workspace_id: str
    environment_id: str
    environment: Environment
    identity_id: str
    identity_type: IdentityType
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    roles: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = SCHEMA_VERSION

    @staticmethod
    def from_dict(data: dict) -> "TenantContext":
        """Build from a raw dict. Raises ValueError for invalid enum values so a
        malformed context is a normalization error, not a silent default."""
        if not isinstance(data, dict):
            raise ValueError("tenant context must be an object")
        try:
            environment = Environment(str(data.get("environment", "")))
            identity_type = IdentityType(str(data.get("identity_type", "")))
        except ValueError as exc:
            raise ValueError(f"invalid tenant enum: {exc}") from exc
        roles = tuple(str(r) for r in (data.get("roles") or ()))
        return TenantContext(
            tenant_id=str(data.get("tenant_id", "")),
            workspace_id=str(data.get("workspace_id", "")),
            environment_id=str(data.get("environment_id", "")),
            environment=environment,
            identity_id=str(data.get("identity_id", "")),
            identity_type=identity_type,
            agent_id=(str(data["agent_id"]) if data.get("agent_id") else None),
            session_id=(str(data["session_id"]) if data.get("session_id") else None),
            roles=roles,
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
        )
