"""Incremental trajectory v2: chain risk, dedup, isolation, decay, expiry."""
import unittest

from enums import ReasonCode
from trajectory.incremental_state import TrajectoryStore


class TestTrajectory(unittest.TestCase):
    def _chain(self, store, tid="traj-1", tenant="A"):
        store.update(tenant_id=tenant, trajectory_id=tid, event_id="e1", capability_id="secret.read")
        store.update(tenant_id=tenant, trajectory_id=tid, event_id="e2", capability_id="filesystem.write")
        return store.update(tenant_id=tenant, trajectory_id=tid, event_id="e3", capability_id="network.egress")

    def test_sensitive_then_egress_chain(self):
        state, signals = self._chain(TrajectoryStore())
        self.assertEqual(state.version, 3)
        self.assertTrue(any(s.reason_code == ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS for s in signals))

    def test_duplicate_event(self):
        store = TrajectoryStore()
        store.update(tenant_id="A", trajectory_id="t", event_id="e1", capability_id="secret.read")
        _, signals = store.update(tenant_id="A", trajectory_id="t", event_id="e1", capability_id="secret.read")
        self.assertTrue(any(s.reason_code == ReasonCode.TRAJECTORY_DUPLICATE_EVENT for s in signals))

    def test_tenant_isolation(self):
        store = TrajectoryStore()
        self._chain(store, tid="shared", tenant="A")
        # Tenant B, same trajectory_id, only one benign event -> no chain, version 1.
        state_b, signals_b = store.update(
            tenant_id="B", trajectory_id="shared", event_id="b1", capability_id="mcp.invoke")
        self.assertEqual(state_b.version, 1)
        self.assertFalse(any(s.reason_code == ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS for s in signals_b))

    def test_risk_decay(self):
        t = [0.0]
        store = TrajectoryStore(decay_half_life_s=100.0, clock=lambda: t[0])
        self._chain(store)  # risk elevated
        peak = store.update(tenant_id="A", trajectory_id="traj-1", event_id="e4",
                            capability_id="mcp.invoke")[0].risk_score
        t[0] = 200.0  # two half-lives later
        decayed = store.update(tenant_id="A", trajectory_id="traj-1", event_id="e5",
                               capability_id="mcp.invoke")[0].risk_score
        self.assertLess(decayed, peak)

    def test_expiry_resets(self):
        t = [0.0]
        store = TrajectoryStore(ttl_s=10.0, clock=lambda: t[0])
        store.update(tenant_id="A", trajectory_id="t", event_id="e1", capability_id="secret.read")
        t[0] = 100.0  # past ttl
        state, _ = store.update(tenant_id="A", trajectory_id="t", event_id="e2", capability_id="mcp.invoke")
        self.assertEqual(state.version, 1)          # fresh trajectory
        self.assertFalse(state.saw_sensitive_read)  # prior sensitive read expired


if __name__ == "__main__":
    unittest.main()
