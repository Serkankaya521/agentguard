import os
import asyncio
from typing import Dict, Any, List
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel, Field

from core.fuzzer import GeneticSemanticFuzzer
from core.adapter import LiveModelAdapter
from core.mcp_interceptor import MCPSecurityInterceptor
from core.trajectory_graph import TrajectoryGraph

load_dotenv()

app = FastAPI(
    title="AgentGuard Core Security Engine",
    description="EU AI Act & OWASP Uyumlu Otonom Ajan Güvenlik ve Denetim API'si",
    version="1.0.0"
)

# Global Servis Örnekleri
mcp_guard = MCPSecurityInterceptor()
active_trajectories: Dict[str, TrajectoryGraph] = {}

# --- Pydantic Şemaları ---
class FuzzRequest(BaseModel):
    seed_prompt: str
    target_keywords: List[str] = Field(default_factory=lambda: ["secret", "override", "key", "admin"])
    population_size: int = 4
    max_generations: int = 2

class ToolInterceptRequest(BaseModel):
    agent_id: str = "default-agent"
    tool_name: str
    arguments: Dict[str, Any]

# --- API Endpoint'leri ---

@app.get("/")
def read_root():
    return {
        "service": "AgentGuard Autonomous Security Engine",
        "status": "ONLINE",
        "modules": ["Genetic Fuzzer", "MCP Interceptor", "Trajectory Graph Engine"]
    }

@app.post("/api/v1/intercept")
def intercept_tool_call(req: ToolInterceptRequest):
    """
    1. MCP Seviyesinde anlık parametre denetimi yapar.
    2. Eylem Çizgesine (Trajectory Graph) düğüm ekleyip çok adımlı anomali riskini analiz eder.
    """
    # 1. Kalkan Denetimi
    verdict = mcp_guard.intercept(req.tool_name, req.arguments)
    
    # 2. Çizge Takibi
    if req.agent_id not in active_trajectories:
        active_trajectories[req.agent_id] = TrajectoryGraph(agent_id=req.agent_id)
    
    graph = active_trajectories[req.agent_id]
    graph.add_step(req.tool_name, req.arguments)
    health = graph.evaluate_trajectory_health()

    return {
        "interception": verdict.dict(),
        "trajectory_health": health
    }

@app.post("/api/v1/fuzz")
async def run_semantic_fuzzing(req: FuzzRequest):
    """
    Verilen çekirdek saldırıyı genetik mutasyonlara sokarak hedef modeli test eder.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY bulunamadı.")

    adapter = LiveModelAdapter(
        model_name="gemini/gemini-3.6-flash",
        api_key=api_key,
        delay_between_calls=3.0
    )

    fuzzer = GeneticSemanticFuzzer(
        population_size=req.population_size,
        max_generations=req.max_generations
    )

    results = await fuzzer.evolve(
        seed_prompt=req.seed_prompt,
        target_keywords=req.target_keywords,
        eval_coroutine=adapter.execute_prompt
    )

    return {
        "status": "COMPLETED",
        "total_mutations_evaluated": len(results),
        "vulnerabilities_detected": len([r for r in results if r.fitness_score >= 0.7]),
        "findings": [
            {
                "fitness_score": r.fitness_score,
                "mutations": r.mutations_applied,
                "payload": r.prompt,
                "response": r.response_sample[:200] if r.response_sample else ""
            }
            for r in results
        ]
    }

@app.websocket("/ws/trajectory/{agent_id}")
async def trajectory_stream(websocket: WebSocket, agent_id: str):
    """
    Dashboard'lar ve frontend için anlık çizge risk durumunu canlı yayınlayan WebSocket kanalı.
    """
    await websocket.accept()
    if agent_id not in active_trajectories:
        active_trajectories[agent_id] = TrajectoryGraph(agent_id=agent_id)
        
    graph = active_trajectories[agent_id]

    try:
        while True:
            health = graph.evaluate_trajectory_health()
            await websocket.send_json(health)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass