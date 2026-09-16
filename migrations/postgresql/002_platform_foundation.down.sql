-- This migration contains immutable audit and workflow history. It is reversible
-- only when none of its domain tables contain records.
DO $$ DECLARE tab text; count_rows bigint; BEGIN
  FOREACH tab IN ARRAY ARRAY['identities','memberships','assets','tool_capabilities','approval_requests','approval_decisions','approval_tokens','findings','policies','evidence_objects','outbox','event_dlq','jobs'] LOOP
    EXECUTE format('SELECT count(*) FROM platform.%I',tab) INTO count_rows;
    IF count_rows > 0 THEN RAISE EXCEPTION 'Nonempty table platform.%: preserve data and roll back application',tab; END IF;
  END LOOP;
END $$;
DROP TABLE platform.jobs,platform.event_dlq,platform.outbox,platform.event_sequences,platform.evidence_objects,
  platform.policies,platform.findings,platform.approval_tokens,platform.approval_decisions,
  platform.approval_requests,platform.tool_capabilities,platform.assets,platform.memberships,
  platform.identities CASCADE;
DROP TRIGGER chain_audit ON platform.audit;
DROP FUNCTION platform.chain_audit();
DROP FUNCTION platform.verify_audit_chain(uuid);
ALTER TABLE platform.audit DISABLE TRIGGER immutable_audit;
ALTER TABLE platform.audit DROP COLUMN record_hash, DROP COLUMN prev_hash;
ALTER TABLE platform.audit ENABLE TRIGGER immutable_audit;
ALTER TABLE platform.credentials DROP COLUMN created_at,DROP COLUMN label,DROP COLUMN credential_id;
ALTER TABLE platform.credentials DROP CONSTRAINT credentials_role_check;
ALTER TABLE platform.credentials ADD CONSTRAINT credentials_role_check CHECK(role IN ('admin','reader'));
