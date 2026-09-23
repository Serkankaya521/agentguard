"""End-to-end: the runtime pipeline produces analytics records the ClickHouse
consumer (Developer B) accepts — schema-valid, tenant header reconciles, no payload."""
import json

from analytics import ClickHouseAnalytics
from hot_path.analytics_publisher import AnalyticsEventPublisher
from security_event_forwarder import ANALYTICS_TOPIC, forward
from policy_enforcement import RuntimeGatewayPipeline
from capability_registry import CapabilityRegistry


def raw_event(tenant_id="11111111-1111-1111-1111-111111111111"):
    return {
        "event_id": "evt-1", "trace_id": "trace-1", "occurred_at": "2026-09-12T00:00:00Z",
        "source": "mcp", "tool_id": "safe_echo", "payload_hash": "sha256:abc",
        "arguments": {"secret_card": "4111111111111111"},
        "tenant": {"schema_version": "1.0.0", "tenant_id": tenant_id, "workspace_id": "ws-1",
                   "environment_id": "env-prod", "environment": "production",
                   "identity_id": "svc-1", "identity_type": "service"},
    }


class CapturingClickHouse(ClickHouseAnalytics):
    """Real insert_security_event logic (schema + tenant checks); transport captured."""

    def __init__(self):
        self.rows = []
        super().__init__("http://clickhouse.local", transport=self._capture)

    def _capture(self, query, body=b"", params=None):
        for line in body.decode().splitlines():
            self.rows.append(json.loads(line))
        return b""


def drive_pipeline():
    pipe = RuntimeGatewayPipeline(CapabilityRegistry())
    decision = pipe.process(raw_event(), "mcp")
    return pipe.analytics_publisher, decision


def test_pipeline_record_is_ingested_by_the_consumer_via_header():
    publisher, decision = drive_pipeline()
    producer = _RecordingProducer()
    assert forward(publisher.drain(), producer)["sent"] == 1
    topic, tenant_header, body = producer.messages[0]
    assert topic == ANALYTICS_TOPIC

    # Exactly what analytics_main does: authenticate by the Kafka header, then insert.
    sink = CapturingClickHouse()
    sink.insert_security_event(tenant_header, body)
    (row,) = sink.rows
    assert row["tenant_id"] == raw_event()["tenant"]["tenant_id"]
    assert row["action_state"] == decision.action_state.value
    assert "secret_card" not in json.dumps(row)  # payload never reached analytics


def test_consumer_rejects_a_forged_tenant_header():
    publisher, _ = drive_pipeline()
    (record,) = publisher.drain()
    sink = CapturingClickHouse()
    try:
        sink.insert_security_event("99999999-9999-9999-9999-999999999999", record["event"])
        raise AssertionError("expected TENANT_CONTEXT_MISMATCH")
    except ValueError as exc:
        assert "TENANT_CONTEXT_MISMATCH" in str(exc)


class _RecordingProducer:
    def __init__(self):
        self.messages = []

    def publish(self, topic, *, key, value, headers):
        tenant_header = dict(headers)["tenant_id"].decode()
        self.messages.append((topic, tenant_header, json.loads(value)))
