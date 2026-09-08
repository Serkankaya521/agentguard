from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class ActionNode(BaseModel):
    """Ajanın gerçekleştirdiği tekil bir eylem/durum düğümü."""
    step_id: int
    action_type: str  # e.g., READ_DB, WRITE_FS, EXTERNAL_NET, USER_OUTPUT
    tool_name: str
    arguments: Dict[str, Any]
    risk_weight: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class TrajectoryEdge(BaseModel):
    """İki eylem arasındaki geçiş ve veri akış ilişkisi."""
    from_step: int
    to_step: int
    data_flow_risk: float = 0.0
    context_note: str = ""

class TrajectoryGraph:
    """
    AgentGuard Yönlü Eylem Çizgesi (Action Trajectory Graph Analyzer).
    Ajanın durum geçişlerini analiz ederek kümülatif veri sızıntılarını ve mantık anomalilerini yakalar.
    """

    def __init__(self, agent_id: str = "primary-agent"):
        self.agent_id = agent_id
        self.nodes: List[ActionNode] = []
        self.edges: List[TrajectoryEdge] = []
        self.cumulative_risk: float = 0.0

    def add_step(self, tool_name: str, arguments: Dict[str, Any]) -> ActionNode:
        """Yeni bir eylem düğümü ekler ve önceki düğümle risk ilişkisini kurar."""
        step_id = len(self.nodes) + 1
        t_lower = tool_name.lower()
        
        # Eylem tipi ve taban risk ağırlığı sınıflandırması
        if any(k in t_lower for k in ["sql", "db", "query"]):
            action_type = "READ_DB"
            weight = 0.2
        elif any(k in t_lower for k in ["file", "fs", "write", "read"]):
            action_type = "FILE_SYSTEM"
            weight = 0.3
        elif any(k in t_lower for k in ["http", "api", "fetch", "webhook"]):
            action_type = "EXTERNAL_NET"
            weight = 0.5
        else:
            action_type = "INTERNAL_LOGIC"
            weight = 0.1

        node = ActionNode(
            step_id=step_id,
            action_type=action_type,
            tool_name=tool_name,
            arguments=arguments,
            risk_weight=weight
        )
        self.nodes.append(node)

        # Önceki düğümle kenar (edge) bağlantısı ve akış riski analizi
        if step_id > 1:
            prev_node = self.nodes[-2]
            flow_risk = 0.0
            note = "Normal durum geçişi."

            # Kritik Durum Geçişi 1: Hassas Veri Okuma -> Dış Ağa Gönderme (Exfiltration Trajectory)
            if prev_node.action_type in ["READ_DB", "FILE_SYSTEM"] and action_type == "EXTERNAL_NET":
                flow_risk = 0.8
                note = "YÜKSEK RİSK: Veritabanı/Dosya okuması sonrası doğrudan dış ağa bağlantı tespit edildi!"

            # Kritik Durum Geçişi 2: Dosya Okuma -> Veritabanı Değişikliği
            elif prev_node.action_type == "FILE_SYSTEM" and action_type == "READ_DB":
                flow_risk = 0.4
                note = "Şüpheli dosya tabanlı veri aktarımı."

            edge = TrajectoryEdge(
                from_step=prev_node.step_id,
                to_step=node.step_id,
                data_flow_risk=flow_risk,
                context_note=note
            )
            self.edges.append(edge)

        self._recalculate_cumulative_risk()
        return node

    def _recalculate_cumulative_risk(self):
        """Çizgedeki düğüm ve kenar ağırlıklarını birleştirerek toplam risk skorunu çıkarır."""
        node_sum = sum(n.risk_weight for n in self.nodes)
        edge_sum = sum(e.data_flow_risk for e in self.edges)
        
        # Normalize edilmiş kümülatif skor (0.0 - 1.0)
        raw_score = (node_sum * 0.4) + (edge_sum * 0.6)
        self.cumulative_risk = min(round(raw_score, 2), 1.0)

    def evaluate_trajectory_health(self) -> Dict[str, Any]:
        """Tüm rotayı analiz edip nihai güvenlik kararını döner."""
        has_critical_anomaly = any(e.data_flow_risk >= 0.7 for e in self.edges)
        verdict = "ANOMALY_DETECTED" if has_critical_anomaly or self.cumulative_risk >= 0.7 else "HEALTHY"

        critical_transitions = [e.context_note for e in self.edges if e.data_flow_risk >= 0.5]

        return {
            "agent_id": self.agent_id,
            "total_steps": len(self.nodes),
            "cumulative_risk_score": self.cumulative_risk,
            "trajectory_status": verdict,
            "anomalies_found": critical_transitions,
            "nodes_summary": [{"step": n.step_id, "type": n.action_type, "tool": n.tool_name} for n in self.nodes]
        }