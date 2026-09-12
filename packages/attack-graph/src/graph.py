"""Attack Knowledge Graph model (foundation).

Typed nodes/edges (master arch 12). Tenant-scoped with global technique nodes;
tenant data never leaks across tenants. Mutations are auditable. Full traversal
is an intelligence-plane (async) operation - never the runtime hot path; the
runtime only reads precomputed summaries/risk profiles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class NodeType:
    TENANT = "tenant"; AGENT = "agent"; MODEL = "model"; TOOL = "tool"; MCP = "mcp"
    CAPABILITY = "capability"; RESOURCE = "resource"; IDENTITY = "identity"
    PERMISSION = "permission"; ATTACK = "attack"; TECHNIQUE = "technique"
    FINDING = "finding"; EVIDENCE = "evidence"; FIX = "fix"; REGRESSION = "regression"


class EdgeType:
    USES = "uses"; HAS_CAPABILITY = "has_capability"; ACCESSES = "accesses"
    TARGETS = "targets"; TRIGGERS = "triggers"; AFFECTS = "affects"
    RESOLVES = "resolves"; VALIDATES = "validates"


@dataclass(frozen=True)
class Node:
    node_id: str
    type: str
    tenant_id: Optional[str] = None  # None -> global (e.g. techniques)
    attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    type: str
    attrs: dict = field(default_factory=dict)


class AttackGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._out: dict[str, list[Edge]] = {}
        self.audit_log: list[dict] = []

    def _audit(self, op: str, **kw) -> None:
        self.audit_log.append({"op": op, "at": datetime.now(timezone.utc).isoformat(), **kw})

    def upsert_node(self, node: Node) -> None:
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._audit("upsert_node", node_id=node.node_id, type=node.type, tenant_id=node.tenant_id)

    def add_edge(self, edge: Edge) -> None:
        if edge.src not in self._nodes or edge.dst not in self._nodes:
            raise KeyError("edge endpoints must exist")
        self._out.setdefault(edge.src, []).append(edge)
        self._audit("add_edge", src=edge.src, dst=edge.dst, type=edge.type)

    def node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def neighbors(self, node_id: str, edge_type: Optional[str] = None) -> list[Edge]:
        return [e for e in self._out.get(node_id, []) if edge_type is None or e.type == edge_type]

    def visible_nodes(self, tenant_id: str) -> list[Node]:
        """Tenant's own nodes + global nodes; never another tenant's data."""
        return [n for n in self._nodes.values() if n.tenant_id in (None, tenant_id)]

    def __len__(self) -> int:
        return len(self._nodes)
