-- Runtime egress guard events (B-R3 shadow / B-R4 enforce), persisted for the console.
-- The runtime gateway (Developer A) decides and emits these off the hot path; the
-- control plane only stores and serves them. No secret value is ever recorded — only
-- the match class and reason codes. `would_block` and `applied` stay distinct so a
-- shadow "would have blocked" is never confused with an enforced block.
CREATE TABLE platform.runtime_guard_events (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  guard text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('shadow','enforce')),
  would_block boolean NOT NULL,
  applied boolean NOT NULL,
  match_type text NOT NULL CHECK (match_type IN ('known_secret','generic_marker','mixed','none')),
  severity text NOT NULL,
  reason_codes text[] NOT NULL DEFAULT '{}',
  trace_id text,
  agent_id text,
  session_id text,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES platform.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES platform.environments(tenant_id, id)
);

CREATE INDEX runtime_guard_events_ws_time
  ON platform.runtime_guard_events (tenant_id, workspace_id, occurred_at DESC);

ALTER TABLE platform.runtime_guard_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.runtime_guard_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON platform.runtime_guard_events
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON platform.runtime_guard_events TO ag_control;
