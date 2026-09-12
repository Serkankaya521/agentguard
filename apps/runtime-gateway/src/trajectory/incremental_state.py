"""Incremental Trajectory Engine v2.

Bounded `current state + new signal -> bounded update` (master arch 30.7). Never
reads full history from the DB on the hot path; full recomputation is async
(worker seam). Tenant/session isolated, concurrency-safe, TTL + risk decay,
duplicate/out-of-order handling, and sequence-risk (chain) evidence.

Chain example: secret.read -> filesystem.write -> network.egress.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from typing import Optional

from bounded import DetectorSignal  # packages/detectors/src
from enums import DetectorSeverity, ReasonCode

SENSITIVE_READ = frozenset({"secret.read", "database.read", "identity.read"})
WRITE_CAPS = frozenset({"filesystem.write", "database.write"})
EGRESS_CAPS = frozenset({"network.egress", "network.admin"})

MAX_RECENT = 16
MAX_SEEN_EVENTS = 64


@dataclass(frozen=True)
class TrajectoryState:
    tenant_id: str
    trajectory_id: str
    risk_score: float = 0.0
    recent_capabilities: tuple[str, ...] = field(default_factory=tuple)
    saw_sensitive_read: bool = False
    saw_write: bool = False
    version: int = 0
    last_event_id: Optional[str] = None


class TrajectoryStore:
    """Bounded, tenant/session-isolated incremental trajectory store."""

    def __init__(self, *, max_trajectories: int = 50_000, ttl_s: float = 900.0,
                 decay_half_life_s: float = 300.0, clock=None) -> None:
        self._max = max_trajectories
        self._ttl = ttl_s
        self._half_life = decay_half_life_s
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._states: "OrderedDict[tuple[str, str], tuple[float, TrajectoryState]]" = OrderedDict()
        self._seen: dict[tuple[str, str], deque] = {}

    def _key(self, tenant_id: str, trajectory_id: str) -> tuple[str, str]:
        return (tenant_id, trajectory_id)

    def _decayed(self, risk: float, last_ts: float, now: float) -> float:
        if self._half_life <= 0:
            return risk
        elapsed = max(0.0, now - last_ts)
        return round(risk * (0.5 ** (elapsed / self._half_life)), 4)

    def update(self, *, tenant_id: str, trajectory_id: str, event_id: str,
               capability_id: Optional[str], now: Optional[float] = None
               ) -> tuple[TrajectoryState, list[DetectorSignal]]:
        now = self._clock() if now is None else now
        key = self._key(tenant_id, trajectory_id)
        signals: list[DetectorSignal] = []
        with self._lock:
            # duplicate detection (idempotent within a trajectory)
            seen = self._seen.setdefault(key, deque(maxlen=MAX_SEEN_EVENTS))
            entry = self._states.get(key)
            prev_state = None
            if entry is not None:
                last_ts, prev_state = entry
                if self._ttl > 0 and now - last_ts > self._ttl:
                    prev_state = None  # expired
                    seen.clear()
            if event_id in seen:
                base = prev_state or TrajectoryState(tenant_id, trajectory_id)
                return base, [DetectorSignal("trajectory", ReasonCode.TRAJECTORY_DUPLICATE_EVENT,
                                             DetectorSeverity.LOW, 0.0, {"event_id": event_id})]

            if prev_state is None:
                prev_state = TrajectoryState(tenant_id=tenant_id, trajectory_id=trajectory_id)
                risk = 0.0
            else:
                risk = self._decayed(prev_state.risk_score, entry[0], now)

            saw_sensitive = prev_state.saw_sensitive_read or (capability_id in SENSITIVE_READ)
            saw_write = prev_state.saw_write or (capability_id in WRITE_CAPS)

            if capability_id in EGRESS_CAPS and saw_sensitive:
                risk = min(1.0, risk + 0.6)
                signals.append(DetectorSignal(
                    "trajectory", ReasonCode.TRAJECTORY_SENSITIVE_THEN_EGRESS,
                    DetectorSeverity.HIGH, 0.8, {"chain": "sensitive->egress"}))
            elif saw_sensitive and saw_write:
                risk = min(1.0, risk + 0.2)
                signals.append(DetectorSignal(
                    "trajectory", ReasonCode.TRAJECTORY_CHAIN_RISK,
                    DetectorSeverity.MEDIUM, 0.4, {"chain": "read->write"}))

            recent = (prev_state.recent_capabilities + ((capability_id or "?"),))[-MAX_RECENT:]
            new_state = TrajectoryState(
                tenant_id=tenant_id, trajectory_id=trajectory_id, risk_score=risk,
                recent_capabilities=recent, saw_sensitive_read=saw_sensitive,
                saw_write=saw_write, version=prev_state.version + 1, last_event_id=event_id)

            seen.append(event_id)
            self._states[key] = (now, new_state)
            self._states.move_to_end(key)
            while len(self._states) > self._max:
                old_key, _ = self._states.popitem(last=False)
                self._seen.pop(old_key, None)
            return new_state, signals
