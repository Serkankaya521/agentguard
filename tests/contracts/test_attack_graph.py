"""Attack knowledge graph: typed nodes/edges, audit, isolation, bounded traversal."""
import unittest

from graph import Edge, EdgeType, Node, NodeType
from repository import GraphRepository


class TestGraph(unittest.TestCase):
    def _repo(self):
        r = GraphRepository()
        r.upsert_node(Node("A:agent:1", NodeType.AGENT, tenant_id="A"))
        r.upsert_node(Node("A:tool:pg", NodeType.TOOL, tenant_id="A"))
        r.upsert_node(Node("cap:database.read", NodeType.CAPABILITY, tenant_id=None))
        r.add_edge(Edge("A:agent:1", "A:tool:pg", EdgeType.USES))
        r.add_edge(Edge("A:tool:pg", "cap:database.read", EdgeType.HAS_CAPABILITY))
        return r

    def test_neighbors_and_audit(self):
        r = self._repo()
        self.assertEqual(len(r.graph.neighbors("A:agent:1")), 1)
        self.assertTrue(any(a["op"] == "add_edge" for a in r.graph.audit_log))

    def test_edge_requires_existing_endpoints(self):
        r = self._repo()
        with self.assertRaises(KeyError):
            r.add_edge(Edge("A:tool:pg", "missing", EdgeType.ACCESSES))

    def test_tenant_isolation(self):
        r = self._repo()
        visible_b = {n.node_id for n in r.graph.visible_nodes("B")}
        self.assertNotIn("A:agent:1", visible_b)          # other tenant hidden
        self.assertIn("cap:database.read", visible_b)      # global visible

    def test_bounded_traversal(self):
        r = self._repo()
        visited = r.traverse("A:agent:1", max_depth=3, tenant_id="A")
        self.assertIn("A:tool:pg", visited)
        self.assertIn("cap:database.read", visited)


if __name__ == "__main__":
    unittest.main()
