"""Asynchronous SecurityEvent publisher for the analytics plane (P4).

The ClickHouse consumer (Developer B) ingests normalized SecurityEvents from the
`security.events` topic and requires the authenticated `tenant_id` as a message
header. This publisher buffers, off the hot path, a schema-valid, payload-free
projection of each event tagged with its tenant, for a forwarder to send.

- Off the hot path: filled after the decision latency is already recorded, so it
  never counts toward the SLO (master arch 30.1).
- No payloads: `arguments` and `payload_ref` are dropped; only metadata and the
  content `payload_hash` leave the runtime, keeping raw payloads off the analytics
  plane.
- Post-decision truth: `action_state` is the enforced state (blocked/executed/...),
  not the "proposed" state the event carried in, so blocked != executed downstream.
- Bounded, deduplicated by event_id, load-shed on overflow (P4 must never pressure
  P1-P3); broker lag is Developer B's alerting concern.
"""
from __future__ import annotations

import threading
from collections import deque

from serialization import to_jsonable  # packages/contracts/src

ANALYTICS_PRIORITY = 4

# The metadata the analytics contract needs; deliberately excludes arguments/payload_ref.
_EVENT_FIELDS = ("schema_version", "event_id", "trace_id", "occurred_at", "source",
                 "tool_id", "declared_capability_id", "resource_scope", "trajectory_id",
                 "payload_hash")


class AnalyticsEventPublisher:
    def __init__(self, max_buffer: int = 10_000) -> None:
        self._buffer: deque = deque(maxlen=max_buffer)
        self._seen: deque = deque(maxlen=max_buffer)
        self._seen_set: set[str] = set()
        self._lock = threading.Lock()
        self.dropped = 0
        self.deduped = 0

    def _project(self, event, runtime_decision) -> dict:
        full = to_jsonable(event)
        record = {k: full[k] for k in _EVENT_FIELDS if k in full}
        record["tenant"] = full["tenant"]  # tenant_context; consumer reads workspace/env ids
        # Enforced state, not the inbound "proposed" state.
        record["action_state"] = runtime_decision.action_state.value
        return record

    def publish_event(self, event, runtime_decision) -> bool:
        """Non-blocking enqueue of one analytics record. False if deduped/shed."""
        tenant_id = runtime_decision.tenant_id
        record = {"tenant_id": tenant_id, "event": self._project(event, runtime_decision)}
        with self._lock:
            eid = record["event"].get("event_id") or ""
            key = f"{tenant_id}:{eid}"
            if key in self._seen_set:
                self.deduped += 1
                return False
            if len(self._buffer) >= self._buffer.maxlen:
                self.dropped += 1  # load shedding (P4)
            self._buffer.append(record)
            self._seen.append(key)
            self._seen_set.add(key)
            while len(self._seen_set) > self._seen.maxlen:
                self._seen_set.discard(self._seen.popleft())
        return True

    def drain(self) -> list[dict]:
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            return items

    def requeue(self, records) -> None:
        """Put already-projected records back at the front (e.g. a failed send)."""
        with self._lock:
            for record in reversed(list(records)):
                if len(self._buffer) >= self._buffer.maxlen:
                    self.dropped += 1
                self._buffer.appendleft(record)

    def pending(self) -> int:
        with self._lock:
            return len(self._buffer)
