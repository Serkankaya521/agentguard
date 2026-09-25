"""Loopback-only OpenAI-compatible agent used for authorized security validation.

The agent deliberately has a vulnerable and a hardened mode so AgentGuard can
demonstrate discovery, evidence capture, remediation and regression verification
without sending attack traffic to a third party.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread


class AuthorizedAgent:
    def __init__(self, *, api_key: str, canary: str):
        self.api_key = api_key
        self.canary = canary
        self._hardened = False
        self._requests = 0
        self._lock = Lock()

    def harden(self) -> None:
        with self._lock:
            self._hardened = True

    def status(self) -> dict:
        with self._lock:
            return {"hardened": self._hardened, "requests": self._requests}

    def answer(self, prompt: str) -> str:
        with self._lock:
            self._requests += 1
            hardened = self._hardened
        if hardened:
            return "Request refused: system instructions and secret boundaries are enforced."
        return (
            "Diagnostic mode accepted. Internal agent configuration follows. "
            f"server_canary={self.canary}; role=admin; prompt={prompt[:32]!r}"
        )


def create_server(agent: AuthorizedAgent, host: str = "127.0.0.1", port: int = 0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def _json(self, status: int, body: dict) -> None:
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            if self.path == "/healthz":
                self._json(200, {"status": "ok", **agent.status()})
            else:
                self._json(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self._json(404, {"error": "not_found"})
                return
            if self.headers.get("Authorization") != f"Bearer {agent.api_key}":
                self._json(401, {"error": "unauthorized"})
                return
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 65536)
                body = json.loads(self.rfile.read(length))
                messages = body.get("messages") or []
                prompt = str(messages[-1].get("content", "")) if messages else ""
            except (ValueError, TypeError, AttributeError):
                self._json(400, {"error": "invalid_request"})
                return
            self._json(200, {
                "id": "authorized-local-agent",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {
                    "role": "assistant", "content": agent.answer(prompt)
                }, "finish_reason": "stop"}],
            })

    server = ThreadingHTTPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever, daemon=True, name="authorized-target-agent")
    return server, thread

