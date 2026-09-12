"""Trajectory full-recomputation worker job (security-owned; off the hot path).

The runtime does bounded incremental updates; authoritative full recomputation
runs here asynchronously (master arch 30.7). Operates on any TrajectoryStore-like
instance provided by the caller (no runtime import).
"""
from __future__ import annotations


class TrajectoryRecomputeJob:
    def recompute(self, store, *, tenant_id: str, trajectory_id: str, events: list[dict]):
        """Replay ordered events into a fresh store to get authoritative state."""
        state = None
        for ev in events:
            state, _ = store.update(tenant_id=tenant_id, trajectory_id=trajectory_id,
                                    event_id=ev["event_id"], capability_id=ev.get("capability_id"))
        return state
