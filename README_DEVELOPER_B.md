# Developer B — Platform / Enterprise

Developer B owns the tenant-aware platform, enterprise workflows, persistence, operations, and user-facing control plane. This document defines scope; implementation remains the developer's responsibility.

## Owned Areas

- `apps/control-api/`
- platform-owned jobs in `apps/worker/`
- `apps/web-console/`
- `packages/auth/`
- `packages/observability/`
- `infra/`
- `migrations/`
- platform semantics in shared contracts and tests

## Platform Responsibilities

- organizations, workspaces, environments, users, and service identities;
- RBAC/ABAC, SSO, and SCIM groundwork;
- asset and capability registry management;
- policy authoring, validation, versioning, and approval workflows;
- finding lifecycle, remediation, reporting, and integrations;
- PostgreSQL, Redis, event backbone, ClickHouse, and object-storage operations;
- immutable or tamper-evident audit access;
- tenant-aware quotas, billing hooks, retention, and operational controls;
- web console, deployment, and platform CI/CD.

## v3.1 Performance Responsibilities

- build the policy publication pipeline from validation through signed compiled artifacts;
- deliver versioned cache-invalidation events without making the Control Plane a hot-path dependency;
- operate Redis and the event backbone with bounded latency, backpressure, DLQs, and lag alerts;
- enforce workload priority and noisy-neighbor isolation across tenants;
- keep PostgreSQL, ClickHouse, reporting, and large payload transfer off the normal runtime path;
- provide load and failure environments for 1K/10K requests per second, bursts, cold cache, datastore slowdown, broker outage, and invalidation storms;
- expose performance, cache, queue, and tenant-isolation telemetry.

## Shared Boundaries

Coordinate with Developer A before changing schemas, capability semantics, policy decisions, approval tokens, evidence requirements, runtime metadata, risk profiles, or worker priorities.

Developer B supplies explicit tenant, identity, environment, and capability context. The Control Plane and UI display runtime decisions but never reproduce or override their security logic.

## Required Handoff

For each completed unit, report migrations, schema versions, tenant-isolation behavior, authorization checks, event and cache effects, observability, load/failure validation, deployment impact, rollback steps, known limitations, and the next security-core dependency.
