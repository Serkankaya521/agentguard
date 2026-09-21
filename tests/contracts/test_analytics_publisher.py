"""Analytics SecurityEvent publisher + forwarder: shape, no-payload, header, best-effort."""
import json
import unittest

from hot_path.analytics_publisher import AnalyticsEventPublisher
from security_event_forwarder import ANALYTICS_TOPIC, BackgroundForwarder, forward
from enums import (ActionState, CacheSource, Decision, Environment, EventSource,
                   FailMode, IdentityType, ReasonCode)
from decisions import RuntimeDecision
from security_event import SecurityEvent
from tenant import TenantContext


def tenant():
    return TenantContext(tenant_id="A", workspace_id="w", environment_id="e",
                         environment=Environment.PRODUCTION, identity_id="i",
                         identity_type=IdentityType.SERVICE, session_id="s1", agent_id="ag1")


def event(event_id="e1", **kw):
    base = dict(event_id=event_id, trace_id="tr", occurred_at="2026-09-12T00:00:00Z",
                source=EventSource.MCP, action_state=ActionState.PROPOSED, tenant=tenant(),
                tool_id="pay", payload_hash="sha256:x", declared_capability_id="payment.execute",
                arguments={"card": "4111111111111111", "cvv": "123"}, payload_ref="s3://raw/secret")
    base.update(kw)
    return SecurityEvent(**base)


def decision(event_id="e1", action_state=ActionState.BLOCKED, tenant_id="A"):
    return RuntimeDecision(
        decision_id="d-" + event_id, tenant_id=tenant_id, event_id=event_id, trace_id="tr",
        policy_version="builtin/1.0.0", policy_hash="sha256:p", runtime_version="rt",
        risk_score=0.9, reason_codes=(ReasonCode.EXEC_GATE_DENIED,),
        cache_source=CacheSource.COMPUTED, latency_us=1, trajectory_version=0,
        decision=Decision.BLOCK, fail_mode=FailMode.FAIL_CLOSED,
        action_state=action_state, capability_id="payment.execute")


class FakeProducer:
    def __init__(self, *, fail_first=0):
        self.sent = []
        self.fail_first = fail_first

    def publish(self, topic, *, key, value, headers):
        if self.fail_first > 0:
            self.fail_first -= 1
            raise ConnectionError("broker down")
        self.sent.append((topic, key, value, dict(headers)))


class TestAnalyticsPublisher(unittest.TestCase):
    def test_record_carries_post_decision_state_and_no_payload(self):
        pub = AnalyticsEventPublisher()
        self.assertTrue(pub.publish_event(event(), decision(action_state=ActionState.BLOCKED)))
        (record,) = pub.drain()
        self.assertEqual(record["tenant_id"], "A")
        body = record["event"]
        self.assertEqual(body["action_state"], "blocked")          # not the inbound "proposed"
        self.assertEqual(body["tenant"]["tenant_id"], "A")
        self.assertEqual(body["payload_hash"], "sha256:x")
        self.assertNotIn("arguments", body)                        # no raw payload leaves runtime
        self.assertNotIn("payload_ref", body)

    def test_dedup_and_drain_clears(self):
        pub = AnalyticsEventPublisher()
        self.assertTrue(pub.publish_event(event("e1"), decision("e1")))
        self.assertFalse(pub.publish_event(event("e1"), decision("e1")))  # same tenant+event id
        self.assertEqual(pub.deduped, 1)
        self.assertEqual(len(pub.drain()), 1)
        self.assertEqual(pub.pending(), 0)

    def test_load_shed_is_bounded(self):
        pub = AnalyticsEventPublisher(max_buffer=2)
        for i in range(5):
            pub.publish_event(event(f"e{i}"), decision(f"e{i}"))
        self.assertEqual(pub.pending(), 2)
        self.assertEqual(pub.dropped, 3)


class TestForwarder(unittest.TestCase):
    def test_sends_to_topic_with_tenant_header_and_matching_body(self):
        pub = AnalyticsEventPublisher()
        pub.publish_event(event("e1"), decision("e1"))
        producer = FakeProducer()
        result = forward(pub.drain(), producer)
        self.assertEqual(result["sent"], 1)
        topic, key, value, headers = producer.sent[0]
        self.assertEqual(topic, ANALYTICS_TOPIC)
        self.assertEqual(key, b"A")
        self.assertEqual(headers["tenant_id"], b"A")
        self.assertEqual(json.loads(value)["tenant"]["tenant_id"], "A")

    def test_mismatched_header_body_is_dropped_not_sent(self):
        producer = FakeProducer()
        bad = {"tenant_id": "A", "event": {"tenant": {"tenant_id": "B"}}}
        result = forward([bad], producer)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(producer.sent, [])

    def test_failed_sends_are_returned_for_requeue(self):
        pub = AnalyticsEventPublisher()
        pub.publish_event(event("e1"), decision("e1"))
        drained = pub.drain()
        result = forward(drained, FakeProducer(fail_first=1))
        self.assertEqual(result["sent"], 0)
        self.assertEqual(len(result["failed"]), 1)

    def test_background_forwarder_requeues_failures_then_delivers(self):
        pub = AnalyticsEventPublisher()
        pub.publish_event(event("e1"), decision("e1"))
        producer = FakeProducer(fail_first=1)
        fwd = BackgroundForwarder(pub, producer)
        self.assertEqual(fwd.flush_once()["sent"], 0)   # broker down -> requeued
        self.assertEqual(pub.pending(), 1)
        self.assertEqual(fwd.flush_once()["sent"], 1)   # broker back -> delivered
        self.assertEqual(pub.pending(), 0)


if __name__ == "__main__":
    unittest.main()
