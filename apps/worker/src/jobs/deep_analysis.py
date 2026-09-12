"""Deep-analysis worker job (intelligence plane, off the hot path).

Consumes async LearningEvents and confirmed findings; updates episodic memory and
the attack graph; computes Vulnerability DNA; and publishes precomputed risk
profiles the runtime reads from cache. Enforces the core law:

    Learning autonomy does not grant privilege autonomy.

It only writes memory/graph and publishes read-only risk profiles. It never
changes policy, privilege, or deployment.
"""
from __future__ import annotations

from typing import Optional

from vulnerability_dna import from_finding  # packages/aegis/src
from graph import Edge, Node, NodeType, EdgeType  # packages/attack-graph/src

HIGH_RISK_THRESHOLD = 0.70


class DeepAnalysisJob:
    def __init__(self, *, episodic, graph_repo, risk_publisher,
                 evidence_validator=None, high_threshold: float = HIGH_RISK_THRESHOLD) -> None:
        self._episodic = episodic
        self._graph = graph_repo
        self._risk = risk_publisher
        self._evidence_validator = evidence_validator
        self._threshold = high_threshold

    def analyze_learning_events(self, events: list[dict]) -> dict:
        per_tool_risk: dict[tuple[str, str, str], float] = {}
        processed = 0
        for ev in events:
            summary = ev.get("summary", {})
            tenant_id = ev.get("tenant_id")
            tool_id = summary.get("tool_id")
            if not tenant_id or not tool_id:
                continue
            processed += 1
            environment = summary.get("environment", "production")
            risk = float(summary.get("risk_score", 0.0))
            key = (tenant_id, tool_id, environment)
            per_tool_risk[key] = max(per_tool_risk.get(key, 0.0), risk)

            # Graph: tool node + capability edge (tenant-scoped). Proposal only.
            self._graph.upsert_node(Node(node_id=f"{tenant_id}:tool:{tool_id}",
                                         type=NodeType.TOOL, tenant_id=tenant_id,
                                         attrs={"tool_id": tool_id}))
            cap = summary.get("capability_id")
            if cap:
                cap_node = f"cap:{cap}"
                self._graph.upsert_node(Node(node_id=cap_node, type=NodeType.CAPABILITY,
                                             tenant_id=None, attrs={"capability": cap}))
                self._graph.add_edge(Edge(src=f"{tenant_id}:tool:{tool_id}", dst=cap_node,
                                          type=EdgeType.HAS_CAPABILITY))
            # Episodic proposal (unverified until governance).
            self._episodic.record_attempt(
                tenant_id=tenant_id, technique=f"tool:{tool_id}",
                outcome=summary.get("decision", "?"), evidence_backed=False,
                confidence=0.4, source="deep_analysis")

        published = 0
        for (tenant_id, tool_id, environment), risk in per_tool_risk.items():
            if risk >= self._threshold:
                self._risk.publish(self._risk.build_profile(
                    subject_type="tool", subject_id=tool_id, tenant_id=tenant_id,
                    environment=environment, risk_score=risk, confidence=0.6,
                    reason_codes=["aggregated_runtime_risk"], source="deep_analysis"))
                published += 1
        return {"processed": processed, "profiles_published": published, "graph_nodes": len(self._graph.graph)}

    def analyze_finding(self, finding: dict) -> dict:
        """Compute Vulnerability DNA + record episodic/graph for a confirmed finding."""
        dna = from_finding(finding)
        tenant_id = finding.get("tenant_id", "unknown")
        self._episodic.record_attempt(
            tenant_id=tenant_id, technique=finding.get("root_cause", "unknown"),
            outcome="confirmed", evidence_backed=bool(finding.get("evidence_backed")),
            confidence=0.7, source="finding")
        return {"dna_fingerprint": dna.fingerprint(),
                "explainable_features": dna.explainable_features()}
