# Platform contract publication — 1.0.0

ApprovalRequest, ApprovalDecision and JobEnvelope were empty ownership
placeholders before this change. Their first published version is 1.0.0; there
is no earlier wire payload to migrate.

Consumers must reject unknown schema versions and unknown fields. Developer A's
Execution Gate receives a one-use token derived from an approved request; it
continues to validate tenant, tool, capability, agent/session scope, expiry,
signature and nonce. The runtime integration also binds identity, resource and
approval request IDs. Older test/local tokens may omit these optional fields;
platform-issued tokens always include them. Reusable approvals mint a distinct
nonce for every use. Production gateways share the Redis atomic replay guard.

CacheInvalidationEvent, TenantContext, Policy, CompiledPolicy, Finding,
Evidence and ToolCapability remain at 1.0.0 and are unchanged.

The Control API common schema and generated OpenAPI document are now published
at 1.0.0. P1 operational-governance endpoints reuse JobEnvelope 1.0.0 and do
not change any runtime/shared wire contract.

P1 reporting, integration delivery and ClickHouse analytics continue to consume
SecurityEvent 1.0.0 and JobEnvelope 1.0.0 without changing their wire shape.
The generated Control API OpenAPI artifact adds operational endpoints while its
API contract version remains 1.0.0 because these additions are backward compatible.

P2/P3 add SCIM endpoints, OIDC mapping, report schedules and billing usage as
backward-compatible Control API additions. Migration 005 stores tenant-scoped OIDC
and schedule state. No shared runtime contract wire shape changed.
