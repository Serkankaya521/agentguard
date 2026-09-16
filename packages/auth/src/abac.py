"""Bounded ABAC checks layered after RBAC."""
from identity import Principal


def attributes_allow(principal: Principal, *, environment_kind: str | None = None,
                     required: dict[str, object] | None = None) -> bool:
    """Default deny when a policy asks for an attribute the principal lacks."""
    required = required or {}
    for key, value in required.items():
        if principal.attributes.get(key) != value:
            return False
    allowed_environments = principal.attributes.get("environments")
    if environment_kind and allowed_environments is not None:
        return environment_kind in allowed_environments
    return True
