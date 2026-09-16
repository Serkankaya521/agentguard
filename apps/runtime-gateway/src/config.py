"""Runtime gateway constants. The gateway is stateless (master arch 30.10)."""
from __future__ import annotations

RUNTIME_VERSION = "runtime-gateway/0.1.0-a1"

# Hot-path latency budget (master arch 30.2). Enforced/benchmarked from A2.
LATENCY_BUDGET_US = 20_000  # 20 ms critical maximum

# Bound inbound argument payloads carried on the hot path (master arch 30.15).
MAX_INLINE_PAYLOAD_BYTES = 16 * 1024
