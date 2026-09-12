"""Load/failure matrix + performance release gate (master arch 30.18; task plan 29).

Runs the runtime hot path under several scenarios and gates on the SLO. Exits
non-zero if any scenario breaches, so CI can block a latency-regressing release.
Single-process approximation; a full multi-node load/failure environment
(1K/10K rps, real Redis/broker outages, noisy neighbor) is a Developer B/infra
deliverable this suite is designed to plug into.

Usage: python3 benchmarks/load_matrix.py [--n N] [--gate]
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / p) for p in (
    "apps/runtime-gateway/src", "packages/policy/src", "packages/detectors/src",
    "packages/contracts/src", "packages/domain/src")]

from capability_registry import CapabilityRegistry, ToolCapability  # noqa: E402
from cache import TieredCache  # noqa: E402
from enums import ApprovalMode, Sensitivity, SideEffect  # noqa: E402
from policy_enforcement import RuntimeGatewayPipeline  # noqa: E402

SLO = {"p99": 10_000, "max": 20_000}  # microseconds


class _DownL2:
    def available(self): return False
    def get(self, k): return None, False
    def set(self, k, v, ttl_s=None): pass
    def invalidate(self, k): pass


def _reg():
    reg = CapabilityRegistry()
    reg.register(ToolCapability(tool_id="safe_echo", capabilities=("mcp.invoke",),
                                side_effect=SideEffect.NONE, sensitivity=Sensitivity.LOW,
                                approval_mode=ApprovalMode.NEVER, version="1"))
    return reg


def _raw(args=None):
    return {"event_id": "e", "trace_id": "t", "tool_id": "safe_echo", "arguments": args or {"q": "select 1"},
            "tenant": {"schema_version": "1.0.0", "tenant_id": "A", "workspace_id": "w",
                       "environment_id": "e", "environment": "production",
                       "identity_id": "i", "identity_type": "service"}}


def _measure(fn, n):
    lat = sorted(fn() for _ in range(n))
    return {"p50": lat[len(lat)//2], "p99": lat[min(len(lat)-1, int(0.99*len(lat)))], "max": lat[-1]}


def scenarios(n: int) -> dict:
    out = {}

    # warm cache
    p = RuntimeGatewayPipeline(_reg()); raw = _raw()
    for _ in range(500): p.process(raw, "mcp")
    out["warm"] = _measure(lambda: p.process(raw, "mcp").latency_us, n)

    # cold cache: fresh pipeline each call
    out["cold_cache"] = _measure(lambda: RuntimeGatewayPipeline(_reg()).process(_raw(), "mcp").latency_us, max(200, n//20))

    # redis (L2) down -> L1/compute fallback
    pd = RuntimeGatewayPipeline(_reg(), cache=TieredCache(l2=_DownL2()))
    for _ in range(500): pd.process(raw, "mcp")
    out["redis_down"] = _measure(lambda: pd.process(raw, "mcp").latency_us, n)

    # invalidation storm: churn L1 between requests
    pc = RuntimeGatewayPipeline(_reg())
    for _ in range(500): pc.process(raw, "mcp")
    def churn():
        pc._cache.l1.clear()  # simulate invalidation
        return pc.process(raw, "mcp").latency_us
    out["invalidation_storm"] = _measure(churn, max(200, n//10))

    # large payload (bounded/truncated on the hot path)
    big = _raw({"blob": "x" * 200_000})
    out["large_payload"] = _measure(lambda: p.process(big, "mcp").latency_us, max(200, n//10))

    # adversarial ReDoS/complexity input (detectors are bounded)
    adv = _raw({"q": ("a'/*" * 5000)})
    out["adversarial_input"] = _measure(lambda: p.process(adv, "mcp").latency_us, max(200, n//10))

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--gate", action="store_true")
    args = ap.parse_args()

    # throughput on the warm path
    p = RuntimeGatewayPipeline(_reg()); raw = _raw()
    for _ in range(500): p.process(raw, "mcp")
    t0 = time.perf_counter()
    for _ in range(args.n): p.process(raw, "mcp")
    rps = int(args.n / (time.perf_counter() - t0))

    results = scenarios(args.n)
    breached = []
    print(f"Load/failure matrix (n={args.n}, throughput ~{rps} req/s single-thread):")
    print(f"  {'scenario':<20} {'p50':>7} {'p99':>7} {'max':>7}   (us)")
    for name, r in results.items():
        ok = r["p99"] <= SLO["p99"] and r["max"] <= SLO["max"]
        if not ok:
            breached.append(name)
        flag = "OK " if ok else "!! "
        print(f"  {flag}{name:<17} {r['p50']:>7} {r['p99']:>7} {r['max']:>7}")
    if breached:
        print(f"{'RELEASE BLOCKED' if args.gate else 'WARN'}: SLO breached: {breached}")
        return 1 if args.gate else 0
    print("SLO OK across all scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
