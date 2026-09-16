# Control API B1

## Setup

Use Python 3.12+. Install `apps/control-api/requirements.txt`. Provision a dedicated PostgreSQL database and a login role `ag_control` with NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT and a generated password through your secret manager. Do not grant it ownership or membership in elevated roles. Migration 001 expects that role to exist.

Set `MIGRATION_DATABASE_URL` to the database owner connection. Run:

```sh
python migrations/postgresql/migrate.py up
```

An operator provisions an expiring credential in `platform.credentials` using a cryptographically random token (at least 32 random bytes), storing only its SHA-256 hex digest, tenant UUID, identity UUID and `admin` or `reader` role. Deliver the raw token through a secret channel. The tenant UUID is also the organization ID. Operator provisioning intentionally precedes creation of the organization; there is no public tenant registration or membership grant endpoint.

Set `CONTROL_DATABASE_URL` to the restricted `ag_control` connection, with TLS and database password supplied externally. Start:

```sh
uvicorn main:app --app-dir apps/control-api/src --no-access-log --limit-concurrency 64
```

Put it behind authenticated-network/TLS ingress with header, connection, concurrency and read-deadline limits. Uvicorn access logging is disabled to avoid logging user-controlled paths.

## Endpoints

All resource operations require `Authorization: Bearer <opaque token>`.
- `PUT /v1/organizations/{tenant_uuid}` with `{"name":"Example"}` creates the organization for the authenticated tenant only.
- `PUT /v1/workspaces/{uuid}` with `{"name":"Engineering"}` creates a workspace within that organization.
- `PUT /v1/environments/{uuid}` with `{"name":"Staging","workspace_id":"<uuid>","kind":"staging"}` creates an environment under an accessible workspace. Allowed kinds match the existing TenantContext enum.
- `GET /v1/{organizations|workspaces|environments}` lists only the caller's tenant; `limit` defaults to 50, max 100; `after` is the previous page's last UUID.
- `GET /v1/{collection}/{uuid}` reads a resource.
- `PUT` with `If-Match: <current integer version>` updates. Omitted/zero means create. Retrying an identical create returns the existing version-1 resource without a second mutation/audit. Environment parent cannot be changed. Concurrent same-resource creates are serialized in PostgreSQL.
- `DELETE /v1/{collection}/{uuid}` requires a positive `If-Match`. Children prevent parent deletion. A reader cannot write or delete.

All tenant/role fields in bodies are rejected. Responses contain tenant, ID and version. Out-of-tenant reads, updates and deletes return NOT_FOUND. IDs are tenant-local: choosing the same workspace UUID in another tenant creates a distinct object and gives no access to the original.

Stable error codes: UNAUTHENTICATED (401), FORBIDDEN (403), NOT_FOUND (404), CONFLICT / VERSION_CONFLICT / PARENT_IMMUTABLE (409), PAYLOAD_TOO_LARGE (413), INVALID_INPUT (422), DATABASE_UNAVAILABLE / UNSAFE_DATABASE_ROLE (503). Correlation IDs are returned in headers and error bodies. Validation details and DB error strings are not exposed.

Audit is append-only and tenant-scoped, containing identity, action, resource and correlation UUID; no customer content is recorded. RBAC/ABAC and other authenticated HTTP 403 denials are persisted as `authorization.denied` in an independent transaction, while unauthenticated failures retain correlation-only operational logs. All successful mutations require a successful audit insert.

## Tests and rollback

```sh
python -m pytest apps/control-api/tests -q
python -m pytest tests/contracts/test_contracts.py -q
```

Database tests need `B1_TEST_OWNER_DSN` and `B1_TEST_APP_DSN` targeting an **empty disposable database**, with `ag_control` pre-created. They preserve test evidence in that disposable database. Without DSNs, database tests explicitly skip. Never point tests at customer infrastructure. Platform CI provisions this setup automatically.

For an empty installation: `python migrations/postgresql/migrate.py down`. Nonempty rollback is refused. Stop the API and restore its previous version while retaining tables and audit; a data-removal/migration plan requires a separate task. No production deployment was performed.

See `P0_CLOSEOUT_TR.md` and the P1-P3 delivery documents for the completed prototype scope and verification evidence. `B1_GAP_ANALYSIS.md` is retained as a historical pre-closeout assessment.

