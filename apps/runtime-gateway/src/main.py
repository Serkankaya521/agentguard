"""Runtime gateway entry point (stateless, horizontally scalable).

Framework-agnostic factory + handler so the gateway is runnable without a web
framework. A FastAPI app is exposed only if fastapi is installed.
"""
from __future__ import annotations

from typing import Optional
from contextlib import asynccontextmanager
import os

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
    forwarder=None;producer=None
    brokers=os.environ.get('KAFKA_BOOTSTRAP_SERVERS')
    if brokers:
        from security_event_forwarder import BackgroundForwarder,KafkaProducerAdapter
        producer=KafkaProducerAdapter(brokers)
        forwarder=BackgroundForwarder(pipeline.analytics_publisher,producer)

    @asynccontextmanager
    async def lifespan(_app):
        if forwarder:forwarder.start()
        yield
        if forwarder:forwarder.stop()
        if producer:producer.close()

    app = FastAPI(title="AgentGuard Runtime Gateway",lifespan=lifespan)

    @app.get('/health/live')
    def live():
        return {'status':'ok'}

    @app.post("/v1/decide")
    async def decide(request: Request):
        return handle(pipeline, await request.json(), source="http")

    return app


app=build_app()
