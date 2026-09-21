"""Approval-revoke consumer: applies approval.revoked events to the shared replay guard.

The Control Plane publishes one topic per event type, so this subscribes to the
`approval.revoked` topic; every message on it is a revocation whose payload carries
`tenant_id` and `nonces`. Revocation is idempotent, so the offset is committed only
after the guard write succeeds — a backend failure leaves the offset uncommitted and
the pod restarts to redeliver, rather than silently dropping a revocation.

The decision logic lives in the broker-agnostic ApprovalRevocationProcessor
(apps/runtime-gateway/src); this module is only the Kafka/Redis wiring.
"""
import json
import os
import signal

from approval_revocation import ApprovalRevocationProcessor, RevocationBackendError
from platform_cache import ApprovalReplayGuard

REVOKED_TOPIC = "approval.revoked"


def main():
    from kafka import KafkaConsumer
    from redis import Redis

    guard = ApprovalReplayGuard(Redis.from_url(
        os.environ["REDIS_URL"], socket_timeout=0.5, socket_connect_timeout=0.5,
        health_check_interval=30))
    processor = ApprovalRevocationProcessor(guard)
    consumer = KafkaConsumer(
        REVOKED_TOPIC,
        bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"].split(","),
        group_id="agentguard-approval-revoke-v1", enable_auto_commit=False,
        auto_offset_reset="earliest", max_poll_records=200,
        value_deserializer=lambda value: json.loads(value))

    running = True

    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)

    try:
        for record in consumer:
            if not running:
                break
            try:
                processor.process_event(record.value)
            except RevocationBackendError:
                # Guard backend down: do not commit, stop so the pod restarts and
                # the uncommitted offset is redelivered.
                break
            except (ValueError, TypeError):
                # Poison message: it can never match a real nonce, so commit past it
                # rather than block the partition.
                pass
            consumer.commit()
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
