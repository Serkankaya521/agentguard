CREATE TABLE platform.oidc_mappings (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  issuer text NOT NULL CHECK (issuer LIKE 'https://%'),
  audience varchar(255) NOT NULL,
  jwks_url text NOT NULL CHECK (jwks_url LIKE 'https://%'),
  default_role varchar(20) NOT NULL DEFAULT 'reader' CHECK (default_role IN ('admin','editor','approver','reader')),
  enabled boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,issuer,audience),
  FOREIGN KEY(tenant_id) REFERENCES platform.organizations(tenant_id)
);
CREATE TABLE platform.report_schedules (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid,
  created_by uuid NOT NULL,
  report_type varchar(32) NOT NULL CHECK(report_type IN ('findings','audit','runtime_summary')),
  output_format varchar(8) NOT NULL CHECK(output_format IN ('json','csv','pdf')),
  interval_minutes integer NOT NULL CHECK(interval_minutes IN (60,1440,10080,43200)),
  lookback_minutes integer NOT NULL CHECK(lookback_minutes BETWEEN 60 AND 44640),
  enabled boolean NOT NULL DEFAULT true,
  next_run_at timestamptz NOT NULL,
  version integer NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id),
  FOREIGN KEY(tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY(tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id)
);
DO $$ DECLARE tab text; BEGIN
  FOREACH tab IN ARRAY ARRAY['oidc_mappings','report_schedules'] LOOP
    EXECUTE format('ALTER TABLE platform.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE platform.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY tenant_boundary ON platform.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',tab);
  END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE,DELETE ON platform.oidc_mappings,platform.report_schedules TO ag_control;
