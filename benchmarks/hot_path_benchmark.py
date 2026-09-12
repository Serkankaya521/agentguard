"""Hot-path latency benchmark + release gate (master arch 30.17, task plan 29).

Measures the runtime gateway ALLOW path (compiled policy + warm L1 cache) and
compares percentiles to the SLO. Exits non-zero if a threshold is exceeded, so
CI can block a latency-regressing release.

Usage: python3 benchmarks/hot_path_benchmark.py [--n N] [--gate]
Note: single-process microbenchmark; full load/failure matrix (1K/10K rps,
cold cache, Redis loss, noisy neighbor) is a later benchmark deliverable.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for p in ("packages/domain/src", "packages/contracts/src", "packages/policy/src",
          "apps/runtime-gateway/src"):
    sys.path.insert(0, str(ROOT / p))

from capability_registry import CapabilityRegistry, ToolCapability  # noqa: E402
from enums import ApprovalMode, Sensitivity, SideEffect  # noqa: E402
from policy_enforcement import RuntimeGatewayPipeline  # noqa: E402

# SLO thresholds in microseconds (master arch 30.2).
SLO = {"p50": 2_000, "p95": 5_000, "p99": 10_000, "max": 20_000}


def _pipeline() -> RuntimeGatewayPipeline:
    reg = CapabilityRegistry()
    reg.register(ToolCapability(
        tool_id="safe_echo", capabilities=("mcp.invoke",), side_effect=SideEffect.NONE,
        sensitivity=Sensitivity.LOW, approval_mode=ApprovalMode.NEVER, version="1",
        fail_open_allowed=True))
    return RuntimeGatewayPipeline(reg)


def _raw() -> dict:
    return {"event_id": "e", "trace_id": "t", "tool_id": "safe_echo",
            "arguments": {"q": "select 1"},
            "tenant": {"schema_version": "1.0.0", "tenant_id": "A", "workspace_id": "w",
                       "environment_id": "e", "environment": "production",
                       "identity_id": "i", "identity_type": "service"}}


def run(n: int) -> dict:
    pipe, raw = _pipeline(), _raw()
    for _ in range(min(500, n)):  # warm cache (compiled policy + capability in L1)
        pipe.process(raw, "mcp")
    lat = sorted(pipe.process(raw, "mcp").latency_us for _ in range(n))
    def pct(q: float) -> int:
        return lat[min(len(lat) - 1, int(q * len(lat)))]
    return {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99), "max": lat[-1],
            "mean": sum(lat) // len(lat), "n": n}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20_000)
    ap.add_argument("--gate", action="store_true", help="exit non-zero if SLO exceeded")
    args = ap.parse_args()

    r = run(args.n)
    print(f"Hot-path ALLOW benchmark (n={r['n']}, warm L1):")
    breached = []
    for k in ("p50", "p95", "p99", "max"):
        ok = r[k] <= SLO[k]
        flag = "OK " if ok else "!! "
        if not ok:
            breached.append(k)
        print(f"  {flag}{k:>4} = {r[k]:>6} us   (SLO <= {SLO[k]} us)")
    print(f"      mean = {r['mean']} us")
    if breached and args.gate:
        print(f"RELEASE BLOCKED: SLO exceeded for {breached}")
        return 1
    print("SLO OK" if not breached else f"WARN: {breached} over SLO (gate off)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
