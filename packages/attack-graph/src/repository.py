"""Attack graph repository: bounded storage + bounded async-plane traversal.

Similarity/traversal results are hypotheses for prioritization, never confirmed
findings (master arch 21).
"""
from __future__ import annotations

from collections import deque
from typing import Optional

from graph import AttackGraph, Edge, Node


class GraphRepository:
    def __init__(self, max_nodes: int = 1_000_000) -> None:
        self._graph = AttackGraph()
        self._max = max_nodes

    @property
    def graph(self) -> AttackGraph:
        return self._graph

    def upsert_node(self, node: Node) -> None:
        if len(self._graph) >= self._max and self._graph.node(node.node_id) is None:
            raise MemoryError("attack graph node budget exceeded")
        self._graph.upsert_node(node)

    def add_edge(self, edge: Edge) -> None:
        self._graph.add_edge(edge)

    def traverse(self, start: str, *, max_depth: int = 3, max_nodes: int = 1000,
                 tenant_id: Optional[str] = None) -> list[str]:
        """Bounded BFS (async plane). Respects tenant isolation when tenant_id given."""
        visited: list[str] = []
        seen = {start}
        q: deque = deque([(start, 0)])
        while q and len(visited) < max_nodes:
            node_id, depth = q.popleft()
            node = self._graph.node(node_id)
            if node is None:
                continue
            if tenant_id is not None and node.tenant_id not in (None, tenant_id):
                continue  # isolation
            visited.append(node_id)
            if depth >= max_depth:
                continue
            for e in self._graph.neighbors(node_id):
                if e.dst not in seen:
                    seen.add(e.dst)
                    q.append((e.dst, depth + 1))
        return visited
