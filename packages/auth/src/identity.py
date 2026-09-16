"""Authenticated platform identity and tenant scope.

Tenant and authorization claims are populated from server-side persistence. API
payloads are never a source of authority.
"""
from dataclasses import dataclass, field
from typing import Literal

IdentityKind = Literal["user", "service"]


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    identity_id: str
    identity_type: IdentityKind
    organization_role: str | None = None
    workspace_roles: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, object] = field(default_factory=dict)

    def role_for(self, workspace_id: str | None) -> str | None:
        if self.organization_role:
            return self.organization_role
        return self.workspace_roles.get(str(workspace_id)) if workspace_id else None
