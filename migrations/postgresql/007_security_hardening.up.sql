-- Tenant-isolate bootstrap and issued credentials. FORCE protects even table owners.
ALTER TABLE platform.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON platform.credentials
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);

CREATE FUNCTION platform.authenticate_credential(p_token_hash text)
RETURNS TABLE(tenant_id uuid,identity_id uuid,role text,label varchar)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,platform AS $$
  SELECT c.tenant_id,c.identity_id,c.role,c.label
  FROM platform.credentials c
  WHERE c.token_hash=p_token_hash AND NOT c.revoked AND c.expires_at>now()
$$;
REVOKE ALL ON FUNCTION platform.authenticate_credential(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.authenticate_credential(text) TO ag_control;

-- Allow the outbox process to discover tenants without a static deployment list.
-- The function exposes identifiers only and fixes search_path to prevent object shadowing.
CREATE FUNCTION platform.active_tenant_ids() RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,platform AS $$
  SELECT tenant_id FROM platform.organizations ORDER BY tenant_id
$$;
REVOKE ALL ON FUNCTION platform.active_tenant_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform.active_tenant_ids() TO ag_control;

ALTER TABLE platform.tenant_operating_limits
  ADD COLUMN max_campaigns integer NOT NULL DEFAULT 100 CHECK(max_campaigns BETWEEN 1 AND 10000);

-- Hash timestamps in one canonical UTC representation. Rebuild existing links
-- in tenant/id order while the immutable-audit trigger is temporarily disabled.
ALTER TABLE platform.audit DISABLE TRIGGER immutable_audit;
DO $$ DECLARE r record; prior text; lag_tenant uuid; canonical_time text; BEGIN
  FOR r IN SELECT * FROM platform.audit ORDER BY tenant_id,id LOOP
    IF r.tenant_id IS DISTINCT FROM lag_tenant THEN prior := NULL; END IF;
    canonical_time := to_char(r.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    UPDATE platform.audit SET prev_hash=prior,
      record_hash='sha256:' || encode(digest(concat_ws('|',r.tenant_id,r.id,r.identity_id,r.correlation_id,r.action,r.resource_id,canonical_time,coalesce(prior,'')),'sha256'),'hex')
      WHERE tenant_id=r.tenant_id AND id=r.id;
    SELECT record_hash INTO prior FROM platform.audit WHERE tenant_id=r.tenant_id AND id=r.id;
    lag_tenant := r.tenant_id;
  END LOOP;
END $$;
ALTER TABLE platform.audit ENABLE TRIGGER immutable_audit;

CREATE OR REPLACE FUNCTION platform.chain_audit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prior text; canonical_time text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text || ':audit',0));
  SELECT record_hash INTO prior FROM platform.audit WHERE tenant_id=NEW.tenant_id ORDER BY id DESC LIMIT 1;
  canonical_time := to_char(NEW.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  NEW.prev_hash := prior;
  NEW.record_hash := 'sha256:' || encode(digest(concat_ws('|',NEW.tenant_id,NEW.id,NEW.identity_id,NEW.correlation_id,NEW.action,NEW.resource_id,canonical_time,coalesce(prior,'')),'sha256'),'hex');
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION platform.verify_audit_chain(requested_tenant uuid) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE r record; prior text; expected text; canonical_time text;
BEGIN
  IF requested_tenant IS DISTINCT FROM nullif(current_setting('app.tenant_id',true),'')::uuid THEN RETURN false; END IF;
  FOR r IN SELECT * FROM platform.audit WHERE tenant_id=requested_tenant ORDER BY id LOOP
    canonical_time := to_char(r.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    expected := 'sha256:' || encode(digest(concat_ws('|',r.tenant_id,r.id,r.identity_id,r.correlation_id,r.action,r.resource_id,canonical_time,coalesce(prior,'')),'sha256'),'hex');
    IF r.prev_hash IS DISTINCT FROM prior OR r.record_hash IS DISTINCT FROM expected THEN RETURN false; END IF;
    prior := r.record_hash;
  END LOOP;
  RETURN true;
END $$;
