#!/bin/sh
set -eu
: "${MIGRATION_DATABASE_URL:?required}"
: "${BACKUP_DIRECTORY:?required}"
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$BACKUP_DIRECTORY/agentguard-$stamp.dump"
mkdir -p "$BACKUP_DIRECTORY"
pg_dump --dbname="$MIGRATION_DATABASE_URL" --format=custom --no-owner --file="$target"
sha256sum "$target" > "$target.sha256"
printf '%s\n' "$target"
