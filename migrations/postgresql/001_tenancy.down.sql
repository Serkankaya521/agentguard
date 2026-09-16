-- Destructive rollback is permitted only on an empty, disposable deployment.
-- Check as the migration superuser so FORCE RLS cannot hide existing records.
DO $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
  RAISE EXCEPTION 'Rollback requires migration superuser';
 END IF;
 IF EXISTS(SELECT 1 FROM platform.audit) OR EXISTS(SELECT 1 FROM platform.organizations)
 OR EXISTS(SELECT 1 FROM platform.credentials) THEN
  RAISE EXCEPTION 'Nonempty foundation: roll back application; preserve database';
 END IF;
END $$;
DROP SCHEMA platform CASCADE;
