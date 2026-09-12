"""Runtime gateway entry point (stateless, horizontally scalable).

Framework-agnostic factory + handler so the gateway is runnable without a web
framework. A FastAPI app is exposed only if fastapi is installed.
"""
from __future__ import annotations

from typing import Optional

from policy_enforcement import RuntimeGatewayPipeline
from capability_registry import CapabilityRegistry
from serialization import to_jsonable  # packages/contracts/src


def create_gateway(registry: Optional[CapabilityRegistry] = None, **kwargs) -> RuntimeGatewayPipeline:
    return RuntimeGatewayPipeline(registry or CapabilityRegistry(), **kwargs)


def handle(pipeline: RuntimeGatewayPipeline, raw: object, source: str = "http") -> dict:
    return to_jsonable(pipeline.process(raw, source))


def build_app(pipeline: Optional[RuntimeGatewayPipeline] = None):  # pragma: no cover - optional dep
    try:
        from fastapi import FastAPI, Request
    except Exception:
        return None
    pipeline = pipeline or create_gateway()
    app = FastAPI(title="AgentGuard Runtime Gateway")

    @app.post("/v1/decide")
    async def decide(request: Request):
        return handle(pipeline, await request.json(), source="http")

    return app
