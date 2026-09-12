"""CompiledPolicy artifact + a runtime-facing artifact store with rollback.

Runtime consumes only schema-valid, hash/signature-verified, version-compatible
artifacts. Invalid artifacts are never used for a production decision
(master arch 30.6, task plan section 9).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import signing
from serialization import to_jsonable  # packages/contracts/src
from validation import validate  # packages/contracts/src

SCHEMA_VERSION = "1.0.0"


class InvalidArtifact(ValueError):
    pass


@dataclass(frozen=True)
class CompiledPolicy:
    policy_id: str
    policy_version: str
    policy_hash: str
    algorithm: str
    compiled_at: str
    compatibility: dict
    ruleset: dict
    signature: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return to_jsonable(self)

    @staticmethod
    def from_dict(data: dict) -> "CompiledPolicy":
        return CompiledPolicy(
            policy_id=str(data["policy_id"]),
            policy_version=str(data["policy_version"]),
            policy_hash=str(data["policy_hash"]),
            algorithm=str(data.get("algorithm", signing.ALGORITHM)),
            compiled_at=str(data["compiled_at"]),
            compatibility=dict(data.get("compatibility", {})),
            ruleset=dict(data["ruleset"]),
            signature=(str(data["signature"]) if data.get("signature") else None),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
        )


def load_verified(data: dict, *, key: Optional[object] = None,
                  runtime_version: Optional[str] = None) -> CompiledPolicy:
    """Validate schema + integrity + compatibility, or raise InvalidArtifact."""
    errors = validate(data, "compiled_policy")
    if errors:
        raise InvalidArtifact(f"schema invalid: {errors[:3]}")
    ok, reason = signing.verify(data, key)
    if not ok:
        raise InvalidArtifact(reason)
    compiled = CompiledPolicy.from_dict(data)
    min_runtime = compiled.compatibility.get("min_runtime")
    if runtime_version is not None and min_runtime and runtime_version < min_runtime:
        raise InvalidArtifact(f"runtime {runtime_version} < required {min_runtime}")
    return compiled


class PolicyArtifactStore:
    """Holds the active compiled policy plus history for rollback."""

    def __init__(self) -> None:
        self._active: Optional[CompiledPolicy] = None
        self._history: list[CompiledPolicy] = []

    def publish(self, compiled: CompiledPolicy, *, key: Optional[object] = None,
                runtime_version: Optional[str] = None) -> None:
        # Re-verify on publish so a bad artifact can never become active.
        load_verified(compiled.to_dict(), key=key, runtime_version=runtime_version)
        if self._active is not None:
            self._history.append(self._active)
        self._active = compiled

    def active(self) -> Optional[CompiledPolicy]:
        return self._active

    def rollback(self) -> Optional[CompiledPolicy]:
        if not self._history:
            return self._active
        self._active = self._history.pop()
        return self._active
