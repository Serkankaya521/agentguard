"""Tool/resource side-effect observer (Developer A: evidence plane).

Turns what a tool *actually did* — resource mutations, network events, output —
into evidence sources, so a finding rests on observed deterministic state, not a
model's say-so (AGENTS.md #7). Content is hashed, never stored raw (no payload
leaves via evidence).

It also enforces `blocked != executed` at the evidence layer: a decision that was
not executed must have produced no side effects. If side effects are observed for a
non-executed action, `reconcile()` flags an enforcement bypass — the most serious
inconsistency the runtime can report — rather than quietly recording success.

Pure and bounded: no network/LLM/IO; observations are capped and over-cap
observations are counted and dropped.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from serialization import content_hash  # packages/contracts/src
from capture import EvidenceSource  # packages/evidence/src

# Kinds that, on an executed action, evidence a real change (see capture.SUCCESS_KINDS).
_MUTATION = "resource_mutation"
_NETWORK = "network_event"
_STATE = "deterministic_state"
_READ = "tool_output"  # observed, but not by itself proof of a successful change


@dataclass(frozen=True)
class SideEffectReconciliation:
    consistent: bool
    executed_with_effects: bool
    reasons: tuple[str, ...]


class SideEffectObserver:
    def __init__(self, *, max_observations: int = 1000) -> None:
        self._max = max_observations
        self._obs: list[dict] = []
        self.dropped = 0

    def _add(self, obs: dict) -> None:
        if len(self._obs) >= self._max:
            self.dropped += 1
            return
        self._obs.append(obs)

    # --- observation recorders (content is hashed, never stored raw) -----------
    def resource_mutation(self, resource: str, *, operation: str,
                          before_hash: Optional[str] = None,
                          after_hash: Optional[str] = None) -> None:
        """A create/update/delete. A change is present when before != after, or when
        the operation is create/delete (which are changes by definition)."""
        changed = operation in ("create", "delete") or (before_hash != after_hash)
        self._add({"kind": _MUTATION if changed else _READ, "resource": str(resource),
                   "operation": str(operation), "before_hash": before_hash,
                   "after_hash": after_hash, "changed": changed})

    def resource_read(self, resource: str, *, result_hash: Optional[str] = None) -> None:
        self._add({"kind": _READ, "resource": str(resource), "operation": "read",
                   "result_hash": result_hash, "changed": False})

    def network_event(self, host: str, *, direction: str = "egress",
                      port: Optional[int] = None, bytes_out: Optional[int] = None) -> None:
        self._add({"kind": _NETWORK, "host": str(host), "direction": str(direction),
                   "port": port, "bytes_out": bytes_out, "changed": True})

    def tool_output(self, output: object) -> None:
        text = output if isinstance(output, str) else content_hash(output)
        self._add({"kind": _READ, "output_hash": content_hash(text),
                   "length": len(text) if isinstance(output, str) else None,
                   "changed": False})

    def deterministic_state(self, key: str, value: object) -> None:
        """A confirmed post-condition (e.g. 'row exists now'); a success-kind change."""
        self._add({"kind": _STATE, "key": str(key), "value_hash": content_hash(value),
                   "changed": True})

    # --- outputs --------------------------------------------------------------
    @property
    def observations(self) -> tuple[dict, ...]:
        return tuple(self._obs)

    def had_side_effects(self) -> bool:
        """True if any observation represents a real change (mutation/network/state)."""
        return any(o.get("changed") for o in self._obs)

    def to_evidence_sources(self) -> list[EvidenceSource]:
        sources: list[EvidenceSource] = []
        for i, o in enumerate(self._obs):
            ref = o.get("after_hash") or o.get("result_hash") or o.get("output_hash") \
                or o.get("value_hash") or o.get("host") or o.get("resource") or f"obs-{i}"
            summary = {k: v for k, v in o.items() if k != "kind" and v is not None}
            sources.append(EvidenceSource(o["kind"], str(ref), summary))
        return sources

    def reconcile(self, action_state: str) -> SideEffectReconciliation:
        effects = self.had_side_effects()
        executed = action_state == "executed"
        reasons: list[str] = []
        if not executed and effects:
            # A blocked/proposed/approved-but-not-run action changed real state:
            # enforcement did not actually stop it.
            reasons.append("enforcement_bypass_side_effect_on_" + action_state)
            return SideEffectReconciliation(False, False, tuple(reasons))
        if executed and not effects:
            reasons.append("executed_without_observable_effect")  # read-only / no-op
        return SideEffectReconciliation(True, executed and effects, tuple(reasons))
