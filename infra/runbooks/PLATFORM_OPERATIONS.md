# Platform operations runbook

## Deployment order

1. Provision PostgreSQL roles and secrets through the cluster secret manager.
2. Back up PostgreSQL, run numbered migrations with the owner DSN, then deploy Control API.
3. Verify `/health/ready` reports migration 6 before enabling traffic.
4. Provision Redis Sentinel/HA, Redpanda topics and ACLs, MinIO/S3 buckets, and ClickHouse.
5. Deploy outbox, platform, analytics, retention and security workers, then the
   schedule materializer. Deploy Web Console last.

Runtime Gateway continues from verified local/Redis policy state during Control API,
PostgreSQL, ClickHouse, report or integration outages. P4/P5 jobs retry with bounded
backoff and move to DLQ after their attempt limit. P1/P2 worker resources remain
reserved by separate deployments.

The security worker must receive `CONTROL_DATABASE_URL`, tenant IDs, evidence-store
settings and only the `env://` target credentials/canaries referenced by campaigns.
Platform workers must not claim `red_team.execute` or `regression.execute` jobs.

## Backup and restore

Run `infra/scripts/backup-postgres.sh` from a restricted backup identity. Encrypt
the resulting custom-format dump in the backup system and copy it to immutable
storage. At least weekly, restore the latest dump into an empty isolated database
with `verify-postgres-restore.sh`. The verifier checks migration checksums and every
tenant's audit hash chain. Never restore into production as a verification step.

S3/MinIO evidence and report buckets require versioning, server-side encryption,
object-lock retention for evidence, and lifecycle deletion for expired reports.
Audit rows are never deleted by application retention jobs; archive partitions to
WORM storage before any operator-managed database maintenance.

## Rollback

Application rollback uses the previous immutable image. Additive migrations stay in
place when domain data exists. A numbered down migration may run only when it accepts
the database as empty. Policy rollback is performed through the Control API and emits
a versioned invalidation event.

## Failure checks

- Redis: confirm runtime local-cache behavior and replay-guard fail-closed policy.
- Broker: monitor outbox depth/age; restore service, then replay DLQ by tenant.
- PostgreSQL: reject new control-plane writes with stable 503 codes; runtime remains independent.
- ClickHouse: analytics endpoint returns 503; ingestion resumes from committed Kafka offsets.
- Object store: evidence registration and report completion stop; jobs retry without losing DB state.
- Integration destination: ensure retry/DLQ contains error codes only, never payload secrets.

All outbound integration hosts must be present in `INTEGRATION_ALLOWED_HOSTS`; production
network policy should also force egress through an allowlisted proxy to prevent DNS rebinding.
