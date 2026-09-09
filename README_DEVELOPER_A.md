# Developer A — Core Security / AEGIS

Developer A owns the real-time security boundary and AgentGuard's security intelligence. This document defines scope; implementation remains the developer's responsibility.

## Owned Areas

- `apps/runtime-gateway/`
- security-owned jobs in `apps/worker/`
- `packages/policy/`
- `packages/detectors/`
- `packages/aegis/`
- `packages/attack-graph/`
- `packages/evidence/`
- security semantics in shared contracts and tests

## v3.1 Runtime Responsibilities

- keep the hot path deterministic, bounded, LLM-independent, and horizontally scalable;
- implement L1/L2 cache lookup and event-driven invalidation;
- consume immutable compiled policy artifacts;
- implement strict timeouts, circuit breakers, and capability-specific fail modes;
- update trajectory state incrementally without loading full history;
- consume precomputed AEGIS risk profiles from cache;
- publish evidence, audit, telemetry, and learning events asynchronously;
- record required runtime decision metadata and latency;
- protect P1/P2 resources from learning, analytics, and red-team workloads;
- meet benchmarked p50/p95/p99 and maximum latency release gates.

## Security Intelligence Responsibilities

- four-part AEGIS memory;
- attack planner and controlled adaptive amplification;
- evolutionary fuzzing and chain exploration;
- attack knowledge graph;
- vulnerability DNA and similarity matching;
- evidence validation;
- remediation regression engine;
- detector and strategy governance;
- AgentGuard-vs-AgentGuard testing;
- safety budgets and kill-switch semantics.

## Shared Boundaries

Coordinate with Developer B before changing schemas, persistence assumptions, cache invalidation, event delivery, approval semantics, identity/tenant context, deployment topology, or observability fields.

Developer A does not infer tenant context and does not implement runtime risk decisions in the web console. Heavy intelligence work must remain off the hot path.

## Required Handoff

For each completed unit, report changed contracts, decision semantics, evidence/audit output, failure modes, safety limits, focused tests, performance measurements, known limitations, and the next platform dependency.
