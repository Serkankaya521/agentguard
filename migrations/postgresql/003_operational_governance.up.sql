CREATE TABLE platform.tenant_operating_limits (
  tenant_id uuid PRIMARY KEY REFERENCES platform.organizations(tenant_id),
  max_assets integer NOT NULL DEFAULT 1000 CHECK (max_assets BETWEEN 1 AND 1000000),
  max_integrations integer NOT NULL DEFAULT 20 CHECK (max_integrations BETWEEN 0 AND 10000),
  max_daily_reports integer NOT NULL DEFAULT 100 CHECK (max_daily_reports BETWEEN 0 AND 100000),
  audit_retention_days integer NOT NULL DEFAULT 3650 CHECK (audit_retention_days BETWEEN 365 AND 36500),
  evidence_retention_days integer NOT NULL DEFAULT 365 CHECK (evidence_retention_days BETWEEN 30 AND 36500),
  report_retention_days integer NOT NULL DEFAULT 90 CHECK (report_retention_days BETWEEN 1 AND 3650),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE platform.usage_daily (
  tenant_id uuid NOT NULL REFERENCES platform.organizations(tenant_id),
  usage_date date NOT NULL DEFAULT current_date,
  metric varchar(64) NOT NULL CHECK (metric IN ('reports_requested','evidence_bytes','events_ingested')),
  amount bigint NOT NULL DEFAULT 0 CHECK (amount >= 0),
  PRIMARY KEY (tenant_id,usage_date,metric)
);

CREATE TABLE platform.integrations (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid,
  integration_type varchar(32) NOT NULL CHECK (integration_type IN
    ('webhook','email','slack','teams','jira','servicenow','siem','github','gitlab')),
  name varchar(120) NOT NULL CHECK (length(trim(name)) > 0),
  endpoint text,
  secret_ref text,
  enabled boolean NOT NULL DEFAULT true,
  configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(configuration)='object'),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,name),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id)
);

CREATE TABLE platform.reports (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid,
  requested_by uuid NOT NULL,
  report_type varchar(32) NOT NULL CHECK (report_type IN ('findings','audit','runtime_summary')),
  output_format varchar(8) NOT NULL CHECK (output_format IN ('json','csv','pdf')),
  period_start timestamptz NOT NULL,
  period_end timestamptz NOT NULL,
  status varchar(16) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','expired')),
  object_key text,
  object_hash varchar(64),
  size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes BETWEEN 0 AND 1073741824),
  error_code varchar(64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY (tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id),
  CHECK (period_end > period_start AND period_end-period_start <= interval '31 days'),
  CHECK (object_key IS NULL OR object_key LIKE tenant_id::text || '/reports/%')
);

DO $$ DECLARE tab text; BEGIN
  FOREACH tab IN ARRAY ARRAY['tenant_operating_limits','usage_daily','integrations','reports'] LOOP
    EXECUTE format('ALTER TABLE platform.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE platform.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY tenant_boundary ON platform.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',tab);
  END LOOP;
END $$;

GRANT SELECT,INSERT,UPDATE,DELETE ON platform.tenant_operating_limits,platform.usage_daily,
  platform.integrations,platform.reports TO ag_control;

COMMENT ON TABLE platform.tenant_operating_limits IS 'Tenant quotas and retention controls; audit retention has a 365-day safety floor.';
COMMENT ON COLUMN platform.integrations.secret_ref IS 'Reference to an external secret manager; never plaintext credentials.';
