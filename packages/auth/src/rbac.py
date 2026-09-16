"""Small, default-deny role permission map for the platform control plane."""
from identity import Principal

ROLE_PERMISSIONS = {
    "owner": frozenset({"*"}),
    "admin": frozenset({
        "tenant.read", "tenant.write", "identity.manage", "asset.manage",
        "capability.manage", "policy.manage", "approval.request",
        "approval.decide", "finding.manage", "evidence.read", "audit.read",
        "operations.read", "operations.manage", "integration.read",
        "integration.manage", "report.read", "report.manage",
        "analytics.read",
        "billing.read", "schedule.manage", "sso.manage", "campaign.manage",
    }),
    "editor": frozenset({
        "tenant.read", "asset.manage", "capability.manage", "policy.manage",
        "approval.request", "finding.manage", "evidence.read",
        "operations.read", "integration.read", "integration.manage",
        "report.read", "report.manage",
        "analytics.read",
        "billing.read", "schedule.manage", "campaign.manage",
    }),
    "approver": frozenset({
        "tenant.read", "approval.request", "approval.decide", "finding.manage",
        "evidence.read",
        "operations.read", "integration.read", "report.read",
        "analytics.read",
        "billing.read",
    }),
    "reader": frozenset({"tenant.read", "evidence.read", "operations.read",
                          "integration.read", "report.read", "analytics.read", "billing.read"}),
}


def permits(principal: Principal, permission: str, workspace_id: str | None = None) -> bool:
    role = principal.role_for(workspace_id)
    allowed = ROLE_PERMISSIONS.get(role or "", frozenset())
    return "*" in allowed or permission in allowed
