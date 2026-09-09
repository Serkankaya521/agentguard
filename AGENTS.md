# AgentGuard Development Guide for Coding Agents

This file is the operational architecture guide for AI coding assistants working in this repository. Read it before inspecting tasks, proposing changes, or writing code.

## 1. Repository State

AgentGuard is transitioning from a Python research prototype to the Enterprise v3 architecture.

- Root-level Python files and `core/` contain the legacy prototype.
- `apps/`, `packages/`, `schemas/`, `infra/`, `migrations/`, and `tests/` define the Enterprise v3 foundation.
- Most v3 files are intentionally blank ownership placeholders. An empty file does not represent an implemented feature.
- Do not present planned v3 capabilities as working behavior.
- Do not rewrite or delete legacy code unless the assigned task explicitly includes migration or removal.

## 2. Product Goal

AgentGuard is an AI agent security platform spanning runtime defense, MCP and tool-call enforcement, authorized autonomous red teaming, adaptive attack research, continuous learning, attack knowledge, evidence-backed findings, remediation verification, and enterprise governance.

The central security principle is:

> Learning autonomy does not grant privilege autonomy.

AEGIS may learn, generate attacks, propose detectors, and recommend policies. It may not expand its own privileges or deploy a security-affecting change to production.

## 3. Non-Negotiable Architecture Boundaries

1. Tool authority comes from the capability registry, not tool-name inference.
2. Unknown capabilities in critical contexts are denied, sandboxed, or sent for approval according to policy. They are not silently trusted.
3. The Policy Enforcement Point executes a decision; the Policy Decision Point produces it. Keep PEP and PDP responsibilities separate.
4. Every persistent domain record and security event carries explicit tenant context.
5. Core Security never guesses tenant identity or scope.
6. The Control Plane and web console never recreate runtime risk decisions in presentation logic.
7. A model statement is not sufficient evidence of a successful attack. Prefer deterministic state, tool output, policy traces, resource changes, hashes, network events, or telemetry.
8. Blocked attempts and executed actions are different event states and must remain distinguishable.
9. Learning output is a proposal until it passes governance.
10. Audit and evidence records must be immutable or tamper-evident.
11. Red-team execution defaults to non-destructive and stays within written Rules of Engagement.
12. Every privileged or long-running operation must respect safety budgets and a kill switch.

## 4. Deployable Units

### `apps/control-api/`

Platform-facing API for organizations, workspaces, environments, users, RBAC/ABAC, assets, policies, findings, approvals, reports, integrations, service identities, and audit access.

Primary owner: Developer B — Platform / Enterprise.

### `apps/runtime-gateway/`

Security data-plane entry point for event normalization, identity and tenant context, capability lookup, policy enforcement, trajectory signals, execution gating, MCP traffic, evidence capture, and telemetry.

Primary owner: Developer A — Core Security / AEGIS.

### `apps/worker/`

Durable background execution for red-team campaigns, learning, regression, reporting, isolated execution, safety budgets, and kill-switch handling.

Ownership follows the job domain. Security intelligence belongs to Developer A; platform scheduling, persistence, deployment, and operations belong to Developer B. Changes at this boundary require coordination.

### `apps/web-console/`

Tenant administration, asset registry, policy management, findings, approvals, reports, integrations, and operational visibility.

Primary owner: Developer B — Platform / Enterprise.

## 5. Shared Packages

| Package | Responsibility | Owner |
| --- | --- | --- |
| `packages/domain/` | Shared business entities and value objects | Shared |
| `packages/contracts/` | Contract parsing, validation, and compatibility | Shared |
| `packages/policy/` | PEP/PDP, capability registry, risk budgets | Developer A |
| `packages/detectors/` | Deterministic runtime, trajectory, and behavioral detection | Developer A |
| `packages/aegis/` | Memory, planning, learning, attack amplification, vulnerability DNA, regression, governance | Developer A |
| `packages/attack-graph/` | Attack knowledge graph model and repository boundary | Developer A |
| `packages/evidence/` | Evidence capture, validation, and integrity | Developer A |
| `packages/auth/` | Identity, RBAC, ABAC, SSO, and SCIM groundwork | Developer B |
| `packages/observability/` | Traces, metrics, audit correlation, and telemetry | Developer B |

Follow the ownership assigned in the current user request or task description. Do not implement another owner's area merely because its placeholder is empty.

## 6. Mandatory Shared Contracts

Treat `schemas/` as the integration boundary and source of truth for cross-component payloads.

- `schemas/events/security_event.schema.json`
- `schemas/events/learning_event.schema.json`
- `schemas/findings/finding.schema.json`
- `schemas/policies/policy.schema.json`
- `schemas/policies/policy_decision.schema.json`
- `schemas/capabilities/tool_capability.schema.json`
- `schemas/evidence/evidence.schema.json`
- `schemas/tenancy/tenant_context.schema.json`
- `schemas/approvals/approval_request.schema.json`
- `schemas/approvals/approval_decision.schema.json`

When changing a shared contract:

1. increment its version;
2. document the migration;
3. assess backward compatibility;
4. update contract tests;
5. notify the other owner in the handoff.

Do not create private copies of shared contracts inside an app. Generated types may live near consumers, but the versioned schema remains authoritative.

## 7. Runtime Security Pipeline

Preserve this sequence unless an approved architecture decision changes it:

```text
Agent / MCP Client
  → Runtime Gateway
  → normalized SecurityEvent
  → Identity + Tenant + Environment Context
  → Capability Registry
  → Policy Decision Point
      deterministic detectors
      trajectory risk
      behavioral signals
      AEGIS recommendation
  → Decision
      ALLOW | BLOCK | REQUIRE_APPROVAL | SANDBOX | REDACT | STEP_UP_AUTH
  → Execution Gate
  → Tool / MCP / API / Resource
  → Evidence + Telemetry + LearningEvent
```

Each decision should be explainable and correlated where possible through `trace_id`, `tenant_id`, `agent_id`, `session_id`, `trajectory_id`, `event_id`, `policy_decision_id`, and `finding_id`.

## 8. AEGIS Model

AEGIS has four distinct memory types:

- episodic memory for attacks and outcomes;
- semantic memory for validated external and internal security knowledge;
- procedural memory for testing strategies;
- strategic memory for architecture-specific attack effectiveness.

Keep hot, warm, and cold learning separate. Hot learning updates memory and strategy scores without changing model weights. Warm learning creates detector, policy, and attack-template proposals. Cold learning requires curated datasets, poisoning checks, deduplication, offline evaluation, human approval, and a versioned model artifact.

New external threat information is untrusted input. Apply source trust scoring, cross-validation, sandbox reproduction, and controlled knowledge promotion before using it as established knowledge.

## 9. Evidence and Finding Lifecycle

Supported finding states are:

```text
SUSPECTED
VALIDATING
CONFIRMED
FIX_PROPOSED
RETESTING
RESOLVED_VERIFIED
REOPENED
FALSE_POSITIVE
```

A confirmed finding should capture root cause, affected architecture, model and agent type, tool capability, permission and MCP topology, preconditions, successful and failed mutations, side effects, evidence pattern, remediation, and regression fingerprint.

Every resolved finding becomes a permanent regression case. Replay the original exploit, amplified variants, and relevant attack chains. If the weakness returns, mark it `REOPENED` rather than creating unrelated history.

## 10. Governance and Release Safety

AEGIS-generated detectors, strategies, and policies cannot deploy themselves. Security-affecting changes follow:

```text
Proposal
  → Unit Tests
  → Historical Corpus Evaluation
  → False-positive and Performance Evaluation
  → Sandbox
  → Shadow Mode
  → Canary
  → Human Approval
  → Signed Artifact
  → Production
```

Every released version must support rollback. No task may bypass approval, reduce tenant isolation, grant secret access, enable destructive testing, weaken policy, or remove audit history without explicit authorization and the designed governance path.

## 11. Rules of Engagement for Red-Team Work

Before executing a campaign, require explicit values for:

- authorized targets and domains;
- IP/CIDR scope;
- environment;
- time window;
- maximum concurrency and request budget;
- data-handling rules;
- destructive permissions;
- kill-switch owner and mechanism.

Do not run aggressive tests against third parties outside written authorization. Do not interpret “50X” as replaying one payload 50 times; it means controlled exploration across syntax, context, state, role, capability, chain, and route variations within the safety budget.

## 12. How to Work in This Repository

Before coding:

1. identify the assigned owner and exact component;
2. inspect the relevant shared schemas and adjacent boundaries;
3. state whether the task affects tenant context, privilege, evidence, audit, or execution;
4. preserve unrelated developer work and empty placeholders;
5. define the tests and evidence needed to verify the change.

During implementation:

- keep domain logic out of UI components;
- keep runtime decisions out of the Control Plane;
- validate inputs at trust boundaries;
- use explicit types for decisions and lifecycle states;
- propagate correlation and tenant identifiers;
- distinguish provider failures from security findings;
- bound queues, retries, concurrency, memory, and retained trajectory state;
- never commit secrets, customer data, provider responses containing secrets, or production evidence.

Before handoff:

1. run focused unit tests and relevant contract tests;
2. run cross-tenant and approval-bypass tests when applicable;
3. verify audit/evidence output and failure behavior;
4. document schema versions and migrations;
5. report changed files, tests, known limits, and the next integration dependency.

## 13. Legacy Prototype Guidance

The legacy implementation uses heuristic pattern matching, in-process trajectory state, and demonstration scripts. Treat it as a source of behavior and experiments, not the target production architecture.

When migrating legacy behavior:

- write the relevant shared contract first;
- preserve useful test scenarios without preserving unsafe defaults;
- replace tool-name inference with explicit capabilities;
- separate proposed, blocked, approved, and executed actions;
- separate provider errors from evaluation results;
- replace process-local state with a tenant-aware bounded store;
- use measured audit outcomes instead of compliance claims.

## 14. Definition of Done for a Change

A change is complete when its ownership is clear, contracts remain compatible, tenant boundaries are enforced, runtime decisions are explainable, evidence and audit events are produced where required, resource use is bounded, failure paths are tested, and the handoff describes how another component can integrate with it.

If a task conflicts with these boundaries, do not silently relax the architecture. Surface the conflict and request an explicit architecture decision.
