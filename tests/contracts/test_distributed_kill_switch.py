"""Distributed kill switch: cross-instance trip, scopes, caching, fail-safe."""
import unittest

from execution.distributed_kill_switch import DistributedKillSwitch, GLOBAL


class FakeClient:
    """Minimal Redis-like KV. Optionally raises to simulate a backend outage."""
    def __init__(self):
        self.store = {}
        self.error = None
        self.gets = 0

    def set(self, key, value):
        if self.error:
            raise self.error
        self.store[key] = value

    def get(self, key):
        self.gets += 1
        if self.error:
            raise self.error
        return self.store.get(key)

    def delete(self, key):
        if self.error:
            raise self.error
        self.store.pop(key, None)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class TestDistributedKillSwitch(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.clock = Clock()
        self.ks = DistributedKillSwitch(self.client, clock=self.clock, cache_ttl_s=1.0)

    def test_campaign_tenant_and_global_scopes(self):
        self.assertFalse(self.ks.is_tripped(campaign_id="c1", tenant_id="A"))
        self.ks.trip(actor="op", campaign_id="c1")
        self.assertTrue(self.ks.is_tripped(campaign_id="c1", tenant_id="A"))
        self.assertFalse(self.ks.is_tripped(campaign_id="c2", tenant_id="A"))
        self.ks.trip(actor="op", tenant_id="A")
        self.assertTrue(self.ks.is_tripped(campaign_id="c2", tenant_id="A"))
        self.ks.trip(actor="op", global_=True)
        self.assertTrue(self.ks.is_tripped(campaign_id="cX", tenant_id="Z"))

    def test_trip_is_visible_to_a_second_instance(self):
        other = DistributedKillSwitch(self.client, clock=Clock(), cache_ttl_s=1.0)
        self.ks.trip(actor="op", campaign_id="c1")
        self.assertTrue(other.is_tripped(campaign_id="c1"))

    def test_recover_clears_and_is_seen_promptly(self):
        self.ks.trip(actor="op", campaign_id="c1")
        self.assertTrue(self.ks.is_tripped(campaign_id="c1"))
        self.ks.recover(actor="op", campaign_id="c1")
        self.assertFalse(self.ks.is_tripped(campaign_id="c1"))

    def test_negative_result_is_cached_within_ttl(self):
        self.assertFalse(self.ks.is_tripped(campaign_id="c1"))
        gets = self.client.gets
        self.assertFalse(self.ks.is_tripped(campaign_id="c1"))  # served from cache
        self.assertEqual(self.client.gets, gets)
        self.clock.t += 2.0  # cache expired
        self.ks.is_tripped(campaign_id="c1")
        self.assertGreater(self.client.gets, gets)

    def test_positive_is_not_cached_away_so_recover_is_seen(self):
        self.ks.trip(actor="op", campaign_id="c1")
        self.assertTrue(self.ks.is_tripped(campaign_id="c1"))
        # A concurrent instance recovers directly in the store (no local cache pop).
        self.client.delete("ag:kill:campaign:c1")
        self.assertFalse(self.ks.is_tripped(campaign_id="c1"))

    def test_fail_safe_when_backend_unreadable(self):
        self.client.error = ConnectionError("redis down")
        self.assertTrue(self.ks.is_tripped(campaign_id="c1", tenant_id="A"))
        permissive = DistributedKillSwitch(FakeClient(), fail_safe=False)
        permissive._client.error = ConnectionError("down")
        self.assertFalse(permissive.is_tripped(campaign_id="c1"))

    def test_trip_failure_surfaces_to_operator(self):
        self.client.error = ConnectionError("redis down")
        with self.assertRaises(ConnectionError):
            self.ks.trip(actor="op", campaign_id="c1")

    def test_audit_log_records_trip_and_recover(self):
        self.ks.trip(actor="alice", campaign_id="c1")
        self.ks.recover(actor="bob", campaign_id="c1")
        self.assertEqual([(e["op"], e["actor"]) for e in self.ks.audit_log],
                         [("trip", "alice"), ("recover", "bob")])

    def test_unsafe_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            self.ks.trip(actor="op", campaign_id="bad scope!")


class TestGuardedEvaluatorInterop(unittest.TestCase):
    def test_drop_in_for_guarded_evaluator(self):
        # Same is_tripped(campaign_id=, tenant_id=) surface the GuardedEvaluator uses.
        ks = DistributedKillSwitch(FakeClient())
        ks.trip(actor="op", tenant_id="A")
        self.assertTrue(ks.is_tripped(campaign_id="c1", tenant_id="A"))
        self.assertEqual(GLOBAL, "global")


if __name__ == "__main__":
    unittest.main()
