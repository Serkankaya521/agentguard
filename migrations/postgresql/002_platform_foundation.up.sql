CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE platform.credentials DROP CONSTRAINT credentials_role_check;
ALTER TABLE platform.credentials ADD CONSTRAINT credentials_role_check
  CHECK (role IN ('owner','admin','editor','approver','reader'));
ALTER TABLE platform.credentials ADD COLUMN credential_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE platform.credentials ADD COLUMN label varchar(120) NOT NULL DEFAULT 'bootstrap';
ALTER TABLE platform.credentials ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE platform.credentials ADD CONSTRAINT credentials_tenant_credential_unique UNIQUE (tenant_id,credential_id);

CREATE TABLE platform.identities (
  tenant_id uuid NOT NULL REFERENCES platform.organizations(tenant_id),
  id uuid NOT NULL,
  identity_type text NOT NULL CHECK (identity_type IN ('user','service')),
  external_subject varchar(255),
  display_name varchar(120) NOT NULL CHECK (length(trim(display_name)) > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,external_subject)
);

CREATE TABLE platform.memberships (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  identity_id uuid NOT NULL,
  workspace_id uuid,
  role text NOT NULL CHECK (role IN ('owner','admin','editor','approver','reader')),
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE NULLS NOT DISTINCT (tenant_id,identity_id,workspace_id),
  FOREIGN KEY (tenant_id,identity_id) REFERENCES platform.identities(tenant_id,id),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id)
);

CREATE TABLE platform.assets (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  asset_type text NOT NULL CHECK (asset_type IN ('agent','model','mcp_server','tool')),
  name varchar(120) NOT NULL CHECK (length(trim(name)) > 0),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,environment_id,name),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);

CREATE TABLE platform.tool_capabilities (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  tool_asset_id uuid NOT NULL,
  tool_id varchar(255) NOT NULL,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,environment_id,tool_id),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id),
  FOREIGN KEY (tenant_id,tool_asset_id) REFERENCES platform.assets(tenant_id,id)
);

CREATE TABLE platform.approval_requests (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  requester_identity_id uuid NOT NULL,
  tool_id varchar(255) NOT NULL,
  capability_id varchar(255) NOT NULL,
  resource varchar(2048) NOT NULL,
  agent_id varchar(255),
  session_id varchar(255),
  use_mode text NOT NULL CHECK (use_mode IN ('one_time','reusable_scoped')),
  max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 1000),
  required_approvals integer NOT NULL DEFAULT 1 CHECK (required_approvals BETWEEN 1 AND 10),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired','revoked','exhausted')),
  expires_at timestamptz NOT NULL,
  idempotency_key varchar(255) NOT NULL,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id),
  FOREIGN KEY (tenant_id,requester_identity_id) REFERENCES platform.identities(tenant_id,id)
);

CREATE TABLE platform.approval_decisions (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  request_id uuid NOT NULL,
  approver_identity_id uuid NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVE','DENY','REVOKE')),
  reason varchar(1000),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,request_id,approver_identity_id),
  FOREIGN KEY (tenant_id,request_id) REFERENCES platform.approval_requests(tenant_id,id),
  FOREIGN KEY (tenant_id,approver_identity_id) REFERENCES platform.identities(tenant_id,id)
);

CREATE TABLE platform.approval_tokens (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  request_id uuid NOT NULL,
  nonce varchar(255) NOT NULL,
  token_document jsonb NOT NULL CHECK (jsonb_typeof(token_document) = 'object'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,nonce),
  FOREIGN KEY (tenant_id,request_id) REFERENCES platform.approval_requests(tenant_id,id)
);

CREATE TABLE platform.findings (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('SUSPECTED','VALIDATING','CONFIRMED','FIX_PROPOSED','RETESTING','RESOLVED_VERIFIED','REOPENED','FALSE_POSITIVE')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);

CREATE TABLE platform.policies (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  policy_version varchar(120) NOT NULL,
  source_document jsonb NOT NULL CHECK (jsonb_typeof(source_document) = 'object'),
  compiled_document jsonb,
  policy_hash varchar(80),
  signature text,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','retired','rejected')),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,environment_id,policy_version),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);
CREATE UNIQUE INDEX one_active_policy_per_environment
  ON platform.policies(tenant_id,environment_id) WHERE status = 'active';

CREATE TABLE platform.evidence_objects (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  event_id varchar(255) NOT NULL,
  object_key varchar(1024) NOT NULL,
  media_type varchar(255) NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 0 AND 104857600),
  object_hash varchar(80) NOT NULL,
  record_hash varchar(80) NOT NULL,
  signature text,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,object_key),
  CHECK (object_key LIKE tenant_id::text || '/%'),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);

CREATE TABLE platform.event_sequences (
  tenant_id uuid NOT NULL,
  namespace varchar(120) NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  PRIMARY KEY (tenant_id,namespace)
);
CREATE TABLE platform.outbox (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  namespace varchar(120) NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  event_type varchar(120) NOT NULL,
  priority text NOT NULL CHECK (priority IN ('P1','P2','P3','P4','P5')),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  last_error_code varchar(120),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,namespace,sequence)
);
CREATE INDEX outbox_ready ON platform.outbox(priority,available_at,created_at)
  WHERE published_at IS NULL;
CREATE TABLE platform.event_dlq (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  source_event_id uuid NOT NULL,
  namespace varchar(120) NOT NULL,
  payload jsonb NOT NULL,
  error_code varchar(120) NOT NULL,
  failed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  replayed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,source_event_id)
);

CREATE TABLE platform.jobs (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid,
  environment_id uuid,
  job_type varchar(120) NOT NULL,
  priority text NOT NULL CHECK (priority IN ('P1','P2','P3','P4','P5')),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','retry','dead_letter')),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
  not_before timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_until timestamptz,
  idempotency_key varchar(255) NOT NULL,
  last_error_code varchar(120),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,idempotency_key),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);
CREATE INDEX jobs_ready ON platform.jobs(priority,not_before,created_at)
  WHERE status IN ('queued','retry');

ALTER TABLE platform.audit ADD COLUMN prev_hash varchar(80);
ALTER TABLE platform.audit ADD COLUMN record_hash varchar(80);
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

CREATE FUNCTION platform.chain_audit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prior text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text || ':audit',0));
  SELECT record_hash INTO prior FROM platform.audit WHERE tenant_id=NEW.tenant_id ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := prior;
  NEW.record_hash := 'sha256:' || encode(digest(concat_ws('|',NEW.tenant_id,NEW.id,NEW.identity_id,NEW.correlation_id,NEW.action,NEW.resource_id,NEW.occurred_at,coalesce(prior,'')),'sha256'),'hex');
  RETURN NEW;
END $$;
CREATE TRIGGER chain_audit BEFORE INSERT ON platform.audit FOR EACH ROW EXECUTE FUNCTION platform.chain_audit();
CREATE FUNCTION platform.verify_audit_chain(requested_tenant uuid) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE r record; prior text; expected text;
BEGIN
  IF requested_tenant IS DISTINCT FROM nullif(current_setting('app.tenant_id',true),'')::uuid THEN
    RETURN false;
  END IF;
  FOR r IN SELECT * FROM platform.audit WHERE tenant_id=requested_tenant ORDER BY id LOOP
    expected := 'sha256:' || encode(digest(concat_ws('|',r.tenant_id,r.id,r.identity_id,r.correlation_id,r.action,r.resource_id,r.occurred_at,coalesce(prior,'')),'sha256'),'hex');
    IF r.prev_hash IS DISTINCT FROM prior OR r.record_hash IS DISTINCT FROM expected THEN RETURN false; END IF;
    prior := r.record_hash;
  END LOOP;
  RETURN true;
END $$;

DO $$ DECLARE tab text; BEGIN
  FOREACH tab IN ARRAY ARRAY['identities','memberships','assets','tool_capabilities','approval_requests','approval_decisions','approval_tokens','findings','policies','evidence_objects','event_sequences','outbox','event_dlq','jobs'] LOOP
    EXECUTE format('ALTER TABLE platform.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE platform.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY tenant_boundary ON platform.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',tab);
  END LOOP;
END $$;

GRANT SELECT,INSERT,UPDATE,DELETE ON platform.identities,platform.memberships,platform.assets,
  platform.tool_capabilities,platform.approval_requests,platform.approval_decisions,
  platform.approval_tokens,platform.findings,platform.policies,platform.evidence_objects,
  platform.event_sequences,platform.outbox,platform.event_dlq,platform.jobs TO ag_control;
GRANT SELECT,INSERT,UPDATE ON platform.credentials TO ag_control;
GRANT EXECUTE ON FUNCTION platform.verify_audit_chain(uuid) TO ag_control;

COMMENT ON TABLE platform.outbox IS 'Transactional event publication; consumers deduplicate by tenant_id + id.';
COMMENT ON TABLE platform.approval_tokens IS 'Every reusable approval use receives a fresh signed nonce.';
