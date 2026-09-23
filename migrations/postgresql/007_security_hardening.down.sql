REVOKE ALL ON FUNCTION platform.active_tenant_ids() FROM ag_control;
DROP FUNCTION platform.active_tenant_ids();
REVOKE ALL ON FUNCTION platform.authenticate_credential(text) FROM ag_control;
DROP FUNCTION platform.authenticate_credential(text);
ALTER TABLE platform.tenant_operating_limits DROP COLUMN max_campaigns;

ALTER TABLE platform.audit DISABLE TRIGGER immutable_audit;
DO $$ DECLARE r record; prior text; lag_tenant uuid; BEGIN
  FOR r IN SELECT * FROM platform.audit ORDER BY tenant_id,id LOOP
    IF r.tenant_id IS DISTINCT FROM lag_tenant THEN prior := NULL; END IF;
    UPDATE platform.audit SET prev_hash=prior,
      record_hash='sha256:' || encode(digest(concat_ws('|',r.tenant_id,r.id,r.identity_id,r.correlation_id,r.action,r.resource_id,r.occurred_at,coalesce(prior,'')),'sha256'),'hex')
      WHERE tenant_id=r.tenant_id AND id=r.id;
    SELECT record_hash INTO prior FROM platform.audit WHERE tenant_id=r.tenant_id AND id=r.id;
    lag_tenant := r.tenant_id;
  END LOOP;
END $$;
ALTER TABLE platform.audit ENABLE TRIGGER immutable_audit;

CREATE OR REPLACE FUNCTION platform.chain_audit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prior text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text || ':audit',0));
  SELECT record_hash INTO prior FROM platform.audit WHERE tenant_id=NEW.tenant_id ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := prior;
  NEW.record_hash := 'sha256:' || encode(digest(concat_ws('|',NEW.tenant_id,NEW.id,NEW.identity_id,NEW.correlation_id,NEW.action,NEW.resource_id,NEW.occurred_at,coalesce(prior,'')),'sha256'),'hex');
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION platform.verify_audit_chain(requested_tenant uuid) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE r record; prior text; expected text;
BEGIN
  IF requested_tenant IS DISTINCT FROM nullif(current_setting('app.tenant_id',true),'')::uuid THEN RETURN false; END IF;
  FOR r IN SELECT * FROM platform.audit WHERE tenant_id=requested_tenant ORDER BY id LOOP
    expected := 'sha256:' || encode(digest(concat_ws('|',r.tenant_id,r.id,r.identity_id,r.correlation_id,r.action,r.resource_id,r.occurred_at,coalesce(prior,'')),'sha256'),'hex');
    IF r.prev_hash IS DISTINCT FROM prior OR r.record_hash IS DISTINCT FROM expected THEN RETURN false; END IF;
    prior := r.record_hash;
  END LOOP;
  RETURN true;
END $$;
DROP POLICY tenant_boundary ON platform.credentials;
ALTER TABLE platform.credentials NO FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.credentials DISABLE ROW LEVEL SECURITY;
