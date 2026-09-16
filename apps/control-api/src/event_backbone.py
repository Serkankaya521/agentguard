"""Transactional outbox delivery with bounded retry, DLQ and replay."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Protocol
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from validation import validate


class Producer(Protocol):
    def publish(self, topic: str, *, key: bytes, value: bytes,
                headers: list[tuple[str, bytes]]) -> None: ...


@dataclass(frozen=True)
class DeliveryResult:
    published: int = 0
    retried: int = 0
    dead_lettered: int = 0


class OutboxPublisher:
    """Duplicates are possible after broker success and before DB commit.

    Event IDs are stable so every consumer can deduplicate. Attempts and batch
    size are bounded; lower priority events cannot jump ahead of P1/P2 records.
    """
    def __init__(self, dsn: str, producer: Producer, *, batch_size: int = 100,
                 max_attempts: int = 8):
        if not 1 <= batch_size <= 1000 or not 1 <= max_attempts <= 100:
            raise ValueError("unbounded outbox configuration")
        self.dsn, self.producer = dsn, producer
        self.batch_size, self.max_attempts = batch_size, max_attempts

    def deliver_once(self, tenant_id) -> DeliveryResult:
        counts = {"published": 0, "retried": 0, "dead_lettered": 0}
        with psycopg.connect(self.dsn, row_factory=dict_row,
                             options="-c statement_timeout=5000 -c lock_timeout=1000") as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (str(tenant_id),))
            rows = conn.execute(
                "SELECT * FROM platform.outbox WHERE published_at IS NULL AND available_at<=now() "
                "ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,created_at "
                "FOR UPDATE SKIP LOCKED LIMIT %s", (self.batch_size,),
            ).fetchall()
            for row in rows:
                try:
                    contract = {"cache.invalidation": "cache_invalidation_event"}.get(row["event_type"])
                    if contract:
                        errors = validate(row["payload"], contract)
                        if errors:
                            raise ValueError("schema_invalid")
                    self.producer.publish(
                        row["event_type"], key=str(row["tenant_id"]).encode(),
                        value=json.dumps(row["payload"], separators=(",", ":"), sort_keys=True).encode(),
                        headers=[("event_id", str(row["id"]).encode()),
                                 ("priority", row["priority"].encode())],
                    )
                except Exception as exc:
                    attempts = row["attempts"] + 1
                    error_code = type(exc).__name__[:120]
                    if attempts >= self.max_attempts:
                        conn.execute(
                            "INSERT INTO platform.event_dlq(tenant_id,id,source_event_id,namespace,payload,error_code) "
                            "VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                            (row["tenant_id"], uuid4(), row["id"], row["namespace"],
                             psycopg.types.json.Jsonb(row["payload"]), error_code),
                        )
                        conn.execute("UPDATE platform.outbox SET attempts=%s,last_error_code=%s,published_at=now() WHERE tenant_id=%s AND id=%s",
                                     (attempts,error_code,row["tenant_id"],row["id"]))
                        counts["dead_lettered"] += 1
                    else:
                        delay = min(300, 2 ** attempts)
                        conn.execute("UPDATE platform.outbox SET attempts=%s,last_error_code=%s,available_at=now()+(%s*interval '1 second') WHERE tenant_id=%s AND id=%s",
                                     (attempts,error_code,delay,row["tenant_id"],row["id"]))
                        counts["retried"] += 1
                else:
                    conn.execute("UPDATE platform.outbox SET published_at=now(),last_error_code=NULL WHERE tenant_id=%s AND id=%s",
                                 (row["tenant_id"],row["id"]))
                    counts["published"] += 1
        return DeliveryResult(**counts)

    def replay(self, tenant_id, dlq_id) -> bool:
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(str(tenant_id),))
            row = conn.execute("SELECT * FROM platform.event_dlq WHERE id=%s AND replayed_at IS NULL FOR UPDATE",(dlq_id,)).fetchone()
            if not row:
                return False
            conn.execute("UPDATE platform.outbox SET attempts=0,published_at=NULL,available_at=now(),last_error_code=NULL WHERE id=%s",(row["source_event_id"],))
            conn.execute("UPDATE platform.event_dlq SET replayed_at=now() WHERE id=%s",(dlq_id,))
            return True


class KafkaProducerAdapter:
    def __init__(self, bootstrap_servers: str):
        from kafka import KafkaProducer
        self._producer = KafkaProducer(bootstrap_servers=bootstrap_servers.split(','),
                                       acks="all", enable_idempotence=True,
                                       request_timeout_ms=3000, max_block_ms=3000)

    def publish(self, topic, *, key, value, headers):
        self._producer.send(topic, key=key, value=value, headers=headers).get(timeout=3)
