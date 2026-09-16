"""Policy compiler: validated source -> signed CompiledPolicy artifact.

Publication lifecycle (master arch 30.6): Validate -> Version -> Compile ->
Optimize -> Hash/Sign -> Publish. Developer B owns authoring/publication; this is
the compile + hash/sign step Developer A owns.
"""
from __future__ import annotations

import functools
from datetime import datetime, timezone
from typing import Optional

import signing
from artifacts import CompiledPolicy
from validation import validate  # packages/contracts/src

DEFAULT_MIN_RUNTIME = "runtime-gateway/0.1.0-a1"


class PolicyCompileError(ValueError):
    pass


def default_policy_source() -> dict:
    """The built-in policy - encodes the A1 decision semantics as data."""
    return {
        "schema_version": "1.0.0",
        "policy_id": "builtin",
        "version": "builtin/1.0.0",
        "ruleset": {
            "fail_closed_capabilities": [
                "payment.execute", "secret.read", "identity.admin", "shell.execute",
                "code.execute", "database.delete", "database.write", "network.admin",
                "network.egress", "agent.delegate",
            ],
            "fail_open_capabilities": [],
            "unknown_capability": {"production": "BLOCK", "default": "REQUIRE_APPROVAL"},
            "destructive_side_effects": ["delete", "execute", "admin"],
            "critical_requires_approval": True,
            "risk_weights": {
                "sensitivity": {"low": 0.10, "medium": 0.35, "high": 0.65, "critical": 0.90},
                "side_effect": {"none": 0.0, "read": 0.05, "write": 0.20, "delete": 0.40,
                                 "network": 0.30, "execute": 0.40, "admin": 0.50},
                "unknown": 0.75,
            },
        },
    }


def compile_policy(source: dict, *, key: Optional[object] = None,
                   min_runtime: str = DEFAULT_MIN_RUNTIME) -> CompiledPolicy:
    errors = validate(source, "policy")
    if errors:
        raise PolicyCompileError(f"policy source invalid: {errors[:3]}")

    artifact = {
        "schema_version": "1.0.0",
        "policy_id": source["policy_id"],
        "policy_version": source["version"],
        "algorithm": signing.ALGORITHM,
        "compiled_at": datetime.now(timezone.utc).isoformat(),
        "compatibility": {"min_runtime": min_runtime},
        "ruleset": source["ruleset"],
    }
    artifact["policy_hash"] = signing.compute_hash(artifact)
    artifact["signature"] = signing.sign(artifact, key)

    errors = validate(artifact, "compiled_policy")
    if errors:
        raise PolicyCompileError(f"compiled artifact invalid: {errors[:3]}")
    return CompiledPolicy.from_dict(artifact)


@functools.lru_cache(maxsize=1)
def default_compiled_policy() -> CompiledPolicy:
    return compile_policy(default_policy_source())
