#!/bin/sh
set -eu
: "${RESTORE_TEST_DATABASE_URL:?required}"
: "${BACKUP_FILE:?required}"
sha256sum -c "$BACKUP_FILE.sha256"
pg_restore --dbname="$RESTORE_TEST_DATABASE_URL" --clean --if-exists --no-owner "$BACKUP_FILE"
psql "$RESTORE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT version,checksum FROM public.platform_migrations ORDER BY version"
psql "$RESTORE_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT tenant_id,platform.verify_audit_chain(tenant_id) FROM platform.organizations"
