# Developer A — Core Security + AEGIS: Security Handoff (v3.1)

Status of the Developer A workstream (Sprints A1–A6). Everything here is on
feature branches `feat/dev-a-sprint-a1..a6` (stacked PRs #1→#6 against the shared
repo). Legacy prototype and Developer B areas are untouched.

## What is implemented

| Area | Where | Sprint |
| --- | --- | --- |
| SecurityEvent normalization, tenant/identity/env validation | `apps/runtime-gateway/src/{normalization,context}.py` | A1 |
| Capability Registry enforcement | `packages/policy/src/capability_registry.py` | A1 |
| PEP / PDP (separate) | `packages/policy/src/{pep,pdp,evaluator}.py` | A1–A3 |
| Compiled policy artifact (compile/optimize/sign/verify/rollback) | `packages/policy/src/{compiler,optimizer,signing,artifacts}.py` | A2 |
| L1/L2 tiered cache + event-driven invalidation | `apps/runtime-gateway/src/cache/` | A2 |
| Circuit breaker, latency budget, capability fail-mode | `apps/runtime-gateway/src/hot_path/` | A2 |
| Deterministic detectors (bounded, ReDoS-safe) | `packages/detectors/src/{bounded,runtime}.py` | A3 |
| Incremental Trajectory v2 | `apps/runtime-gateway/src/trajectory/incremental_state.py` | A3 |
| Precomputed risk lookup | `apps/runtime-gateway/src/risk/precomputed.py` | A3 |
| Execution Gate + approval-token validation | `apps/runtime-gateway/src/execution_gate.py` | A3 |
| Async event publisher (off hot path) | `apps/runtime-gateway/src/hot_path/event_publisher.py` | A3 |
| Evidence capture/validation/integrity | `packages/evidence/src/{capture,integrity}.py` | A4 |
| AEGIS four memories + poisoning control | `packages/aegis/src/memory/` | A4 |
| Vulnerability DNA, risk-profile publisher, attack graph | `packages/aegis/src/{vulnerability_dna,risk_profiles}.py`, `packages/attack-graph/src/` | A4 |
| Deep-analysis worker | `apps/worker/src/jobs/deep_analysis.py` | A4 |
| Attack Planner, 50X engine, genetic fuzzer | `packages/aegis/src/{planner,adaptive_attack,evolutionary_search}.py` | A5 |
| Safety budget / RoE, kill switch, sandbox | `apps/worker/src/execution/` | A5 |
| Regression engine + finding lifecycle | `packages/aegis/src/regression.py`, `packages/domain/src/finding.py` | A5 |
| Governance lifecycle + learning tiers | `packages/aegis/src/{governance,learning}.py` | A6 |
| AgentGuard-vs-AgentGuard twin | `packages/aegis/src/red_team_twin.py` | A6 |
| Load/failure matrix + performance release gate | `benchmarks/{hot_path_benchmark,load_matrix}.py` | A6 |

## Enforced boundaries (non-negotiables held)

- Tool authority from the capability registry, never the tool name.
- PEP enforces / PDP decides — kept separate.
- Every decision consumes validated tenant context; blocked ≠ executed.
- Runtime consumes only signed/verified compiled policy; no LLM/graph/big-DB on the hot path.
- Detectors deterministic, bounded, ReDoS-safe.
- Evidence: a model claim alone is not sufficient; integrity hash/HMAC + tamper-evident chain.
- Security intelligence is asynchronous; learning autonomy ≠ privilege autonomy.
- AEGIS cannot self-deploy; production requires the ordered lifecycle + human approval + signature; rollback supported.
- Red-team only under RoE, safety budget, and kill switch; non-destructive by default.
- Runtime performance is a security property (release gate).

## Shared contracts (schemas/, source of truth)

Implemented v1.0.0: `tenant_context`, `tool_capability`, `security_event`,
`policy_decision`, `runtime_decision`, `policy`, `compiled_policy`,
`cache_invalidation_event`, `risk_profile`, `learning_event`, `evidence`, `finding`.

**Developer B to define (seams):** `approval_request`, `approval_decision`,
`job_envelope`.

## Performance (single-process microbenchmarks)

- Warm ALLOW: p50 ~150–170 µs, p99 ~270–350 µs (SLO p50<2ms / p99<10ms).
- Load matrix (warm, cold, redis-down, invalidation storm, large payload,
  adversarial input) all within SLO. Throughput ~5k req/s single-thread.
- Bottleneck: per-request jsonschema validation in normalization (still within SLO).

## Seams Developer B must provide

- Redis (L2) HA + invalidation event publisher; Kafka/Redpanda broker + DLQ.
- Durable stores for policy artifacts, evidence blobs, AEGIS memory/graph, findings.
- Approval workflow (request/decision/approver) producing tokens the Execution Gate validates.
- KMS/asymmetric signing for compiled policy and runtime decisions.
- Campaign scheduling/deployment; sandbox OS/container isolation.
- Multi-node load/failure environment for the full matrix (1K/10K rps, real outages).

## How to run

```
python3 tests/test_runner.py                       # 131 unit/contract/adversarial tests
python3 benchmarks/hot_path_benchmark.py --gate    # hot-path SLO gate
python3 benchmarks/load_matrix.py --gate           # load/failure matrix gate
```

Packaging note: imports use a deterministic path-priority order
(`conftest.py`/`pyproject.toml`/`tests/test_runner.py`) to resolve flat-src
module overlaps. A proper workspace packaging decision (namespaced imports,
hyphenated app dirs, contracts/evidence `validation.py` overlap) is a shared item.

## Sprint A7 — P2 closure + remaining Developer A features

Closes the P2 gaps and the last Developer-A-owned placeholders.

| Area | Where | Item |
| --- | --- | --- |
| Threat-research ingestion + knowledge promotion | `packages/aegis/src/threat_research.py` | #36, #37 |
| Poisoning-resistant trust scoring | `threat_research.py` + `memory/semantic.py` | #38 |
| Attack-template governance | `packages/aegis/src/attack_templates.py` | #39 |
| Shadow/canary evaluation metrics | `packages/aegis/src/evaluation.py` | #40 |
| Model/detector version registry | `packages/aegis/src/versioning.py` | #41 |
| Adversarial corpus management | `packages/aegis/src/corpus.py` | #42 |
| Multi-turn / chain exploration | `packages/aegis/src/chain_explorer.py` | #23 |
| Risk budget (PDP input) | `packages/policy/src/risk_budget.py` | P0 #? risk budgets |
| Behavioral anomaly detector | `packages/detectors/src/behavioral.py` | detector category |
| Runtime evidence capture | `apps/runtime-gateway/src/evidence_capture.py` | evidence |
| MCP source adapter | `apps/runtime-gateway/src/mcp/gateway.py` | runtime source |
| Runtime security telemetry emitter | `apps/runtime-gateway/src/telemetry.py` | observability signals |
| Gateway entry point (framework-agnostic) | `apps/runtime-gateway/src/main.py` | runtime gateway |
| Security worker jobs | `apps/worker/src/jobs/{learning,regression,trajectory_recompute}.py` | security-owned jobs |

**Developer A task-plan status: all 45 areas (P0 1–18, P1 19–34, P2 35–45) implemented and tested.**

## Intentionally left to Developer B (not touched)

- `packages/policy/src/publisher.py` — policy publication lifecycle
- `apps/worker/src/jobs/reporting.py` — reporting
- `apps/worker/src/queues/{backpressure,dlq,priority}.py` — broker/queue infra (producer-side bounded-buffer semantics already in `hot_path/event_publisher.py`)
- `apps/worker/src/{config,main}.py` — worker deployment/scheduling entry
- `apps/control-api/`, `apps/web-console/`, `packages/{auth,observability}/`, `infra/`, `migrations/`

## Test/benchmark totals

`python3 tests/test_runner.py` → **156 tests** pass. Both benchmark gates pass.
