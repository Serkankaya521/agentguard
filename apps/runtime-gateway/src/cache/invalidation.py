"""Event-driven cache invalidation consumer.

Consumes CacheInvalidationEvent (schema-validated), evicting keys from L1 (+L2).
Idempotent (dedupes by event_id) and ordered (drops stale sequence per
namespace). Developer B produces these events; the runtime consumes them.
"""
from __future__ import annotations

from typing import Optional

from validation import validate  # packages/contracts/src


class InvalidationConsumer:
    def __init__(self, l1, l2: Optional[object] = None) -> None:
        self._l1 = l1
        self._l2 = l2
        self._seen_events: set[str] = set()
        self._last_sequence: dict[str, int] = {}

    def process(self, event: dict) -> bool:
        """Return True if applied, False if rejected/duplicate/stale."""
        if validate(event, "cache_invalidation_event"):
            return False
        event_id = event["event_id"]
        if event_id in self._seen_events:
            return False  # idempotent
        namespace = event["namespace"]
        sequence = int(event["sequence"])
        if sequence <= self._last_sequence.get(namespace, -1):
            return False  # out-of-order / stale
        for key in event.get("keys", []):
            full = f"{namespace}:{key}"
            self._l1.invalidate(full)
            self._l1.invalidate_prefix(full)
            if self._l2 is not None:
                self._l2.invalidate(full)
        self._seen_events.add(event_id)
        self._last_sequence[namespace] = sequence
        return True
