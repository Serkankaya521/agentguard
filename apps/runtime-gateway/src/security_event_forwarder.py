"""Forward buffered analytics records to the `security.events` topic.

The analytics consumer requires the authenticated tenant as a Kafka header and
reconciles it against the event body (TENANT_CONTEXT_MISMATCH), so this sends the
`tenant_id` header alongside a body whose tenant matches. Broker-agnostic: it
takes any producer exposing ``publish(topic, *, key, value, headers)`` (e.g.
control-api KafkaProducerAdapter).

Analytics is P4/best-effort: a send failure does not raise. Failed records are
returned so a caller may re-buffer or drop them, and the process moves on rather
than blocking higher-priority work.
"""
from __future__ import annotations

import json
import threading
import time

ANALYTICS_TOPIC = "security.events"


def _encode(record: dict) -> tuple[bytes, bytes, list]:
    tenant_id = str(record["tenant_id"])
    body = record["event"]
    # Defence in depth: the header and body tenant must agree or the consumer rejects it.
    if body.get("tenant", {}).get("tenant_id") != tenant_id:
        raise ValueError("tenant header/body mismatch")
    value = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return tenant_id.encode(), value, [("tenant_id", tenant_id.encode())]


def forward(records, producer) -> dict:
    """Best-effort send. Returns {'sent': int, 'failed': [records]}."""
    sent = 0
    failed = []
    for record in records:
        try:
            key, value, headers = _encode(record)
        except (KeyError, ValueError):
            # Malformed record can never be ingested; drop it (do not retry forever).
            continue
        try:
            producer.publish(ANALYTICS_TOPIC, key=key, value=value, headers=headers)
        except Exception:
            failed.append(record)
        else:
            sent += 1
    return {"sent": sent, "failed": failed}


class BackgroundForwarder:
    """Periodically drains a publisher and forwards to the broker in a daemon thread.

    Opt-in: the stateless gateway holds a producer only where analytics forwarding
    is configured. Failed records are re-buffered so a brief broker blip is not a
    silent loss, while the publisher's own bound still sheds under sustained lag.
    """

    def __init__(self, publisher, producer, *, interval_s: float = 1.0) -> None:
        self._publisher = publisher
        self._producer = producer
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="security-event-forwarder",
                                        daemon=True)

    def flush_once(self) -> dict:
        result = forward(self._publisher.drain(), self._producer)
        if result["failed"]:
            self._publisher.requeue(result["failed"])
        return result

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush_once()
            except Exception:
                pass  # never let the flusher thread die
            self._stop.wait(self._interval_s)

    def start(self) -> "BackgroundForwarder":
        self._thread.start()
        return self

    def stop(self, *, timeout_s: float = 2.0) -> None:
        self._stop.set()
        self._thread.join(timeout=timeout_s)
