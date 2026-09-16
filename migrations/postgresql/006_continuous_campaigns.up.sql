CREATE TABLE platform.campaigns (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  created_by uuid NOT NULL,
  name varchar(120) NOT NULL CHECK(length(trim(name))>0),
  target_type varchar(32) NOT NULL CHECK(target_type='openai_compatible'),
  target_config jsonb NOT NULL CHECK(jsonb_typeof(target_config)='object'),
  secret_ref varchar(512),
  canary_secret_ref varchar(512),
  seed_prompt text NOT NULL CHECK(length(seed_prompt) BETWEEN 1 AND 16384),
  objective_markers jsonb NOT NULL CHECK(jsonb_typeof(objective_markers)='array'),
  request_budget integer NOT NULL CHECK(request_budget BETWEEN 2 AND 10000),
  mutation_budget integer NOT NULL CHECK(mutation_budget BETWEEN 1 AND 100000),
  max_concurrency integer NOT NULL CHECK(max_concurrency=1),
  interval_minutes integer CHECK(interval_minutes BETWEEN 1 AND 10080),
  status varchar(16) NOT NULL DEFAULT 'paused' CHECK(status IN ('active','paused','archived')),
  next_run_at timestamptz,
  version integer NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id),
  FOREIGN KEY(tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id),
  FOREIGN KEY(tenant_id,environment_id) REFERENCES platform.environments(tenant_id,id),
  CHECK(NOT (target_config ?| ARRAY['api_key','token','secret','password','credential'])),
  CHECK(mutation_budget>=request_budget),
  CHECK((status<>'active') OR (interval_minutes IS NOT NULL AND next_run_at IS NOT NULL))
);

CREATE TABLE platform.campaign_runs (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  status varchar(20) NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','stopped')),
  scheduled_for timestamptz NOT NULL,
  started_at timestamptz,
  completed_at timestamptz,
  candidates_evaluated integer NOT NULL DEFAULT 0 CHECK(candidates_evaluated>=0),
  findings_created integer NOT NULL DEFAULT 0 CHECK(findings_created>=0),
  best_score numeric(5,4),
  evidence_object_id uuid,
  error_code varchar(120),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id),
  UNIQUE(tenant_id,campaign_id,scheduled_for),
  FOREIGN KEY(tenant_id,campaign_id) REFERENCES platform.campaigns(tenant_id,id),
  FOREIGN KEY(tenant_id,evidence_object_id) REFERENCES platform.evidence_objects(tenant_id,id)
);

CREATE TABLE platform.campaign_candidates (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  run_id uuid NOT NULL,
  generation integer NOT NULL CHECK(generation>=0),
  lineage jsonb NOT NULL CHECK(jsonb_typeof(lineage)='array'),
  payload text NOT NULL CHECK(length(payload) BETWEEN 1 AND 65536),
  response_hash varchar(64) NOT NULL CHECK(length(response_hash)=64),
  fitness numeric(5,4) NOT NULL CHECK(fitness BETWEEN 0 AND 1),
  evidence_level varchar(24) NOT NULL CHECK(evidence_level IN ('heuristic','target_canary','tool_observation')),
  finding_id uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id),
  FOREIGN KEY(tenant_id,run_id) REFERENCES platform.campaign_runs(tenant_id,id),
  FOREIGN KEY(tenant_id,finding_id) REFERENCES platform.findings(tenant_id,id)
);

CREATE TABLE platform.regression_cases (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  finding_id uuid NOT NULL,
  campaign_id uuid NOT NULL,
  payload text NOT NULL CHECK(length(payload) BETWEEN 1 AND 65536),
  expected_block boolean NOT NULL DEFAULT true,
  status varchar(16) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','passed','reopened')),
  last_run_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,id),
  UNIQUE(tenant_id,finding_id),
  FOREIGN KEY(tenant_id,finding_id) REFERENCES platform.findings(tenant_id,id),
  FOREIGN KEY(tenant_id,campaign_id) REFERENCES platform.campaigns(tenant_id,id)
);

CREATE INDEX campaigns_due ON platform.campaigns(next_run_at) WHERE status='active';
CREATE INDEX campaign_runs_status ON platform.campaign_runs(status,created_at);

DO $$ DECLARE tab text; BEGIN
  FOREACH tab IN ARRAY ARRAY['campaigns','campaign_runs','campaign_candidates','regression_cases'] LOOP
    EXECUTE format('ALTER TABLE platform.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE platform.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY tenant_boundary ON platform.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',tab);
  END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE,DELETE ON platform.campaigns,platform.campaign_runs,
  platform.campaign_candidates,platform.regression_cases TO ag_control;

COMMENT ON COLUMN platform.campaigns.secret_ref IS 'External secret-manager reference; never plaintext credentials.';
COMMENT ON COLUMN platform.campaigns.canary_secret_ref IS 'External reference to a target-side canary unknown to attack payloads.';
