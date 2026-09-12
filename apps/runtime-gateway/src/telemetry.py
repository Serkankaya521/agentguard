"""Runtime security telemetry emitter (Developer A: security signals + metadata).

Emits correlation + decision metadata for the observability collector (Developer
B) to consume. Bounded buffer, non-blocking, no PII/secrets.
"""
from __future__ import annotations

from collections import deque


class TelemetryEmitter:
    def __init__(self, max_buffer: int = 10_000) -> None:
        self._buffer: deque = deque(maxlen=max_buffer)
        self.dropped = 0

    def emit(self, runtime_decision) -> None:
        if len(self._buffer) >= self._buffer.maxlen:
            self.dropped += 1
        self._buffer.append({
            "decision_id": runtime_decision.decision_id,
            "trace_id": runtime_decision.trace_id,
            "tenant_id": runtime_decision.tenant_id,
            "decision": runtime_decision.decision.value,
            "risk_score": runtime_decision.risk_score,
            "cache_source": runtime_decision.cache_source.value,
            "latency_us": runtime_decision.latency_us,
            "policy_version": runtime_decision.policy_version,
            "trajectory_version": runtime_decision.trajectory_version,
        })

    def drain(self) -> list[dict]:
        items = list(self._buffer)
        self._buffer.clear()
        return items
