"""L1/L2 tiered cache + event-driven invalidation."""
import unittest

from cache import InMemoryL2, InvalidationConsumer, L1Cache, TieredCache, make_key
from enums import CacheSource


class TestL1(unittest.TestCase):
    def test_hit_and_miss(self):
        c = L1Cache()
        self.assertEqual(c.get("k"), (None, False))
        c.set("k", 1)
        self.assertEqual(c.get("k"), (1, True))

    def test_lru_eviction(self):
        c = L1Cache(max_size=2)
        c.set("a", 1); c.set("b", 2); c.get("a"); c.set("c", 3)  # b is LRU -> evicted
        self.assertFalse(c.get("b")[1])
        self.assertTrue(c.get("a")[1])
        self.assertTrue(c.get("c")[1])

    def test_single_flight_computes_once(self):
        c = L1Cache()
        calls = {"n": 0}
        def compute():
            calls["n"] += 1
            return 42
        v1, hit1 = c.get_or_compute("k", compute)
        v2, hit2 = c.get_or_compute("k", compute)
        self.assertEqual((v1, v2), (42, 42))
        self.assertFalse(hit1)
        self.assertTrue(hit2)
        self.assertEqual(calls["n"], 1)

    def test_invalidate_prefix(self):
        c = L1Cache()
        c.set("ns:v:-:x", 1); c.set("ns:v:-:y", 2); c.set("other", 3)
        self.assertEqual(c.invalidate_prefix("ns:v:-:"), 2)
        self.assertTrue(c.get("other")[1])


class TestTiered(unittest.TestCase):
    def test_l2_promotion(self):
        l1 = L1Cache(); l2 = InMemoryL2()
        l2.set("k", "from-l2")
        tc = TieredCache(l1, l2)
        def boom():
            raise AssertionError("compute must not run on L2 hit")
        v, src = tc.get_or_compute("k", boom)
        self.assertEqual((v, src), ("from-l2", CacheSource.L2))
        v2, src2 = tc.get_or_compute("k", boom)
        self.assertEqual(src2, CacheSource.L1)

    def test_compute_populates_both_tiers(self):
        l1 = L1Cache(); l2 = InMemoryL2()
        tc = TieredCache(l1, l2)
        v, src = tc.get_or_compute("k", lambda: "computed")
        self.assertEqual((v, src), ("computed", CacheSource.COMPUTED))
        self.assertEqual(l2.get("k"), ("computed", True))


class TestInvalidation(unittest.TestCase):
    def _event(self, event_id, sequence, keys, ns="cap"):
        return {"schema_version": "1.0.0", "event_id": event_id, "sequence": sequence,
                "namespace": ns, "keys": keys, "issued_at": "2026-09-12T00:00:00Z"}

    def test_applies_and_evicts(self):
        l1 = L1Cache(); l1.set("cap:t1", 1)
        cons = InvalidationConsumer(l1)
        self.assertTrue(cons.process(self._event("e1", 0, ["t1"])))
        self.assertFalse(l1.get("cap:t1")[1])

    def test_idempotent_and_ordered(self):
        l1 = L1Cache()
        cons = InvalidationConsumer(l1)
        self.assertTrue(cons.process(self._event("e1", 5, ["a"])))
        self.assertFalse(cons.process(self._event("e1", 6, ["b"])))   # duplicate id
        self.assertFalse(cons.process(self._event("e2", 4, ["c"])))   # stale sequence
        self.assertTrue(cons.process(self._event("e3", 6, ["d"])))    # newer

    def test_schema_invalid_rejected(self):
        l1 = L1Cache()
        cons = InvalidationConsumer(l1)
        self.assertFalse(cons.process({"event_id": "x"}))

    def test_tenant_safe_keys(self):
        self.assertNotEqual(
            make_key("cap", "1", "tool", tenant_id="A"),
            make_key("cap", "1", "tool", tenant_id="B"))


if __name__ == "__main__":
    unittest.main()
