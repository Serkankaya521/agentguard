-- Per-environment egress-guard mode, set by the operator in the console.
-- This is the control-plane store of the `egress_secret_guard` intent (mode + enforce
-- action). The runtime gateway (Developer A) reads it to decide off/shadow/enforce; the
-- console writes it. Default intent is 'shadow' (watch) — never silently off or enforce.
CREATE TABLE platform.runtime_guard_settings (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  guard text NOT NULL DEFAULT 'egress_secret',
  mode text NOT NULL DEFAULT 'shadow' CHECK (mode IN ('off','shadow','enforce')),
  action text NOT NULL DEFAULT 'mask' CHECK (action IN ('mask','stop')),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, environment_id, guard),
  FOREIGN KEY (tenant_id, workspace_id) REFERENCES platform.workspaces(tenant_id, id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES platform.environments(tenant_id, id)
);

ALTER TABLE platform.runtime_guard_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.runtime_guard_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON platform.runtime_guard_settings
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON platform.runtime_guard_settings TO ag_control;
