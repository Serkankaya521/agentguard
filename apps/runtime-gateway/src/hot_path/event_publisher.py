"""Asynchronous learning/telemetry event publisher (off the hot path).

Publishing must never block the decision (master arch 30.1, 30.11-30.12). This
buffers bounded LearningEvents with idempotent ids and load-shedding; a durable
broker/DLQ (Developer B) drains the buffer. Priority order: P1 enforcement,
P2 evidence/audit, P3 learning (this), P4 analytics, P5 red-team.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from serialization import redact, to_jsonable  # packages/contracts/src

LEARNING_PRIORITY = 3


class AsyncEventPublisher:
    def __init__(self, max_buffer: int = 10_000) -> None:
        self._buffer: deque = deque(maxlen=max_buffer)
        self._seen: deque = deque(maxlen=max_buffer)
        self._seen_set: set[str] = set()
        self._lock = threading.Lock()
        self.dropped = 0        # load-shedding counter (buffer overflow)
        self.deduped = 0

    def publish_decision(self, event, runtime_decision) -> bool:
        """Non-blocking enqueue. Returns False if deduped/shed."""
        learning = {
            "schema_version": "1.0.0",
            "event_id": f"le-{runtime_decision.decision_id}",
            "trace_id": runtime_decision.trace_id,
            "tenant_id": runtime_decision.tenant_id,
            "kind": "decision",
            "priority": LEARNING_PRIORITY,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "payload_ref": getattr(event, "payload_hash", None),
            "summary": redact({
                "tool_id": getattr(event, "tool_id", None),
                "environment": getattr(getattr(event, "tenant", None), "environment", None).value
                    if getattr(getattr(event, "tenant", None), "environment", None) is not None else None,
                "agent_id": getattr(getattr(event, "tenant", None), "agent_id", None),
                "decision": runtime_decision.decision.value,
                "action_state": runtime_decision.action_state.value,
                "reason_codes": [r.value for r in runtime_decision.reason_codes],
                "risk_score": runtime_decision.risk_score,
                "capability_id": runtime_decision.capability_id,
                "cache_source": runtime_decision.cache_source.value,
                "latency_us": runtime_decision.latency_us,
                "fail_mode": runtime_decision.fail_mode.value,
            }),
        }
        with self._lock:
            eid = learning["event_id"]
            if eid in self._seen_set:
                self.deduped += 1
                return False
            if len(self._buffer) >= self._buffer.maxlen:
                self.dropped += 1  # load shedding; broker lag would trigger alerts
            self._buffer.append(learning)
            self._seen.append(eid)
            self._seen_set.add(eid)
            while len(self._seen_set) > self._seen.maxlen:
                self._seen_set.discard(self._seen.popleft())
        return True

    def drain(self) -> list[dict]:
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            return items

    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)
