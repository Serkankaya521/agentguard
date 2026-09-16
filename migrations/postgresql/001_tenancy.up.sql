CREATE SCHEMA platform;
CREATE TABLE platform.credentials (
 token_hash text PRIMARY KEY CHECK(length(token_hash)=64), tenant_id uuid NOT NULL,
 identity_id uuid NOT NULL, role text NOT NULL CHECK(role IN ('admin','reader')),
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE platform.organizations (
 tenant_id uuid PRIMARY KEY, id uuid UNIQUE NOT NULL CHECK(id=tenant_id),
 name varchar(120) NOT NULL CHECK(length(trim(name))>0), version integer NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE TABLE platform.workspaces (
 tenant_id uuid NOT NULL REFERENCES platform.organizations(tenant_id), id uuid NOT NULL,
 name varchar(120) NOT NULL CHECK(length(trim(name))>0), version integer NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,name)
);
CREATE TABLE platform.environments (
 tenant_id uuid NOT NULL, id uuid NOT NULL, workspace_id uuid NOT NULL,
 name varchar(120) NOT NULL CHECK(length(trim(name))>0), version integer NOT NULL DEFAULT 1 CHECK(version>0),
 kind text NOT NULL CHECK(kind IN ('production','staging','development','test')),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,workspace_id,name),
 FOREIGN KEY(tenant_id,workspace_id) REFERENCES platform.workspaces(tenant_id,id)
);
CREATE TABLE platform.audit (
 tenant_id uuid NOT NULL, id bigint GENERATED ALWAYS AS IDENTITY,
 identity_id uuid NOT NULL, correlation_id uuid NOT NULL, action text NOT NULL,
 resource_id uuid NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id)
);
CREATE FUNCTION platform.reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit is immutable' USING ERRCODE='42501'; END $$;
CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON platform.audit
 FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_audit_mutation();
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['organizations','workspaces','environments','audit'] LOOP
  EXECUTE format('ALTER TABLE platform.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE platform.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_boundary ON platform.%I USING (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',tab);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA platform FROM PUBLIC;
GRANT USAGE ON SCHEMA platform TO ag_control;
GRANT SELECT ON platform.credentials TO ag_control;
GRANT SELECT,INSERT,UPDATE,DELETE ON platform.organizations,platform.workspaces,platform.environments TO ag_control;
GRANT SELECT,INSERT ON platform.audit TO ag_control;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA platform TO ag_control;
