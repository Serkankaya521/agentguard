"""Regression worker job (security-owned; off the hot path).

Replays regression cases against the current defense and reports PASS/REOPEN.
"""
from __future__ import annotations

from typing import Callable


class RegressionJob:
    def run(self, engine, cases: list, defense: Callable[[str], bool]) -> list[dict]:
        results = []
        for case in cases:
            r = engine.replay(case, defense)
            results.append({"case_id": case.case_id, "passed": r.passed,
                            "reason": r.reason.value,
                            "failing_payloads": list(r.failing_payloads)})
        return results
