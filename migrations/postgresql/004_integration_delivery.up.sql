CREATE TABLE platform.integration_deliveries (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  integration_id uuid NOT NULL,
  event_id varchar(255) NOT NULL,
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  status varchar(16) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
  response_code integer,
  last_error_code varchar(64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,integration_id,event_id),
  FOREIGN KEY (tenant_id,integration_id) REFERENCES platform.integrations(tenant_id,id)
);
ALTER TABLE platform.integration_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.integration_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON platform.integration_deliveries
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON platform.integration_deliveries TO ag_control;
