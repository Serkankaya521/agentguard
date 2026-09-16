# Sprint B1: evidence and first implementation slice

> **Tarihsel belge:** Bu analiz ilk B1 diliminin başlangıç durumunu kaydeder.
> Buradaki açıklar P0-P3 teslimleriyle kapatılmıştır; güncel durum için
> `P0_CLOSEOUT_TR.md` ve `MVP_READINESS_AUDIT_TR.md` belgelerine bakın.

## Baseline evidence

The supplied ZIP was extracted under `agentguard-main/`, preserving all legacy and Developer A files.
`README_MASTER_ARCHITECTURE_v3.1.md`, `AGENTS.md`, and `README_DEVELOPER_B.md` were read.
The requested `README_DEVELOPER_B_v3.1_TR.md` is absent from the archive. The available B ownership guide agrees with the master architecture; there is no identified contradictory instruction.

Before implementation:
- `apps/control-api/src/main.py`, all API modules, repositories/services and its test initializer contained only a newline.
- `packages/auth/src/{identity,rbac,abac,sso,scim}.py` were ownership placeholders.
- `migrations/postgresql/` contained only `.gitkeep`: no tables, RLS, migration runner or rollback.
- `schemas/api/control_api.schema.json` was blank. It is not a usable API contract.
- `schemas/tenancy/tenant_context.schema.json` and `packages/domain/src/tenant.py` define runtime TenantContext 1.0.0, requiring workspace and environment. Organization administration cannot truthfully supply these before they exist.
- Existing repository pytest configuration includes runtime and contract tests, but no Control API tests.

## Selected task analysis

Owner: Developer B, Control API and PostgreSQL migrations. New code remains inside these directories plus platform CI/docs. No Developer A file or shared contract changes.
Identity boundary: high-entropy opaque bearer token, SHA-256 stored only in the operator-provisioned credential table, checked for expiry/revocation on every request. Tenant and admin/reader role come from that record. No tenant or role override from request headers/body. This is service-identity groundwork, not SSO or a user/membership system.
Data boundary: organization ID equals tenant ID; composite workspace/environment keys and FK enforce ancestry; FORCE RLS with transaction-local tenant context; API refuses database superuser, BYPASSRLS and table-owner connections. The migration credential must never be used by the API.
Contract: existing shared TenantContext 1.0.0 remains unchanged. These are administrative resource DTOs, not private TenantContext copies. Versioned `/v1` routes expose generated OpenAPI input/output models. Cross-component API contract publication still needs joint agreement before filling the shared blank schema.
Migration: transactional 001 up/down with advisory lock, ledger and checksum. Down refuses nonempty installations, preserving audit. Existing deployments roll back application binaries while keeping additive tables.
Audit: business writes and append-only audit insert commit together. DB permissions and triggers prohibit UPDATE/DELETE/TRUNCATE for application credentials. Database administrators remain a trust boundary; no WORM or externally anchored cryptographic audit is claimed.
Observability: generated correlation UUID, HTTP status, duration; no paths, tokens, payloads or names in application logs. OTel exporter is still a gap.
Events/cache: no runtime publication, cache or broker consumed by this slice. Reads go to PostgreSQL, so administrative changes need no cache invalidation here. Runtime context delivery/invalidation is an explicit follow-up, not simulated by empty events.
Failure: fail closed on identity or DB failure, bounded connect/query/lock times, atomic rollback on audit failure. HTTP body capped at 4096 bytes and lists at 100 records with UUID keyset pagination. Deployment ingress must also bound concurrent requests, header size and slow request deadlines.
Proof: API and direct-SQL cross-tenant CRUD, role bypass, expired/revoked credential, tenant injection, audit mutation, audit-write failure, FK enforcement, empty upgrade/down/up, nonempty rollback refusal, idempotent create race and optimistic-update race.

## Remaining B1 gaps

The first hierarchy slice does not complete Sprint B1. User memberships, ABAC workspace restrictions, service credential lifecycle endpoints/rotation, OIDC/SSO, OTel export, bounded connection pool/admission control, production ingress, external audit retention and environment-to-runtime context integration remain. This API uses organization-wide admin and reader roles; neither is a workspace-specific permission.
Policy publication, approvals, findings, Redis HA, event backbone, evidence storage and load isolation still need implementation. No runtime risk evaluator was added.
