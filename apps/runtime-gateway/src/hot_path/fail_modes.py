"""Capability fail-mode matrix (master arch 30.13).

Data-driven from the active compiled policy: high-impact capabilities fail
closed; low-risk fail-open only when the policy/capability explicitly allows it.
"""
from __future__ import annotations

from typing import Optional

from capability_registry import ToolCapability  # packages/policy/src
from enums import FailMode
from evaluator import fail_mode_for as _fail_mode_for  # packages/policy/src
from optimizer import OptimizedRuleset  # packages/policy/src


class FailModeMatrix:
    def __init__(self, ruleset: OptimizedRuleset) -> None:
        self._ruleset = ruleset

    def fail_mode_for(self, capability_id: Optional[str],
                      record: Optional[ToolCapability]) -> FailMode:
        return _fail_mode_for(self._ruleset, capability_id, record)

    def is_fail_closed(self, capability_id: Optional[str],
                       record: Optional[ToolCapability]) -> bool:
        return self.fail_mode_for(capability_id, record) == FailMode.FAIL_CLOSED
