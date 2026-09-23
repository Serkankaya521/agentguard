"""P1 operational governance: quotas, retention, integrations and reports."""
from datetime import datetime, timedelta, timezone
import re
from typing import Literal
from uuid import UUID, uuid4

import psycopg
from fastapi import Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from database import Database, audit, enqueue_event

SECRET_REF = re.compile(r"^(?:env|vault|aws-sm|azure-kv|gcp-sm)://[A-Za-z0-9._/:-]{1,500}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OperatingLimitsInput(StrictModel):
    max_assets: int = Field(ge=1, le=1_000_000)
    max_integrations: int = Field(ge=0, le=10_000)
    max_daily_reports: int = Field(ge=0, le=100_000)
    audit_retention_days: int = Field(ge=365, le=36_500)
    evidence_retention_days: int = Field(ge=30, le=36_500)
    report_retention_days: int = Field(ge=1, le=3_650)
    max_campaigns: int = Field(default=100,ge=1,le=10_000)


class IntegrationInput(StrictModel):
    workspace_id: UUID | None = None
    integration_type: Literal['webhook','email','slack','teams','jira','servicenow','siem','github','gitlab']
    name: str = Field(min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, max_length=2048)
    secret_ref: str | None = Field(default=None, max_length=512)
    enabled: bool = True
    configuration: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode='after')
    def secure_destination(self):
        if self.endpoint and not self.endpoint.startswith('https://'):
            raise ValueError('integration endpoints require https')
        if self.secret_ref and not SECRET_REF.fullmatch(self.secret_ref):
            raise ValueError('invalid secret reference')
        forbidden = {'token','password','secret','api_key','credential'} & {k.lower() for k in self.configuration}
        if forbidden:
            raise ValueError('credentials must use secret_ref')
        return self


class ReportInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID | None = None
    report_type: Literal['findings','audit','runtime_summary']
    output_format: Literal['json','csv','pdf']
    period_start: datetime
    period_end: datetime

    @model_validator(mode='after')
    def bounded_period(self):
        if self.period_start.tzinfo is None or self.period_end.tzinfo is None:
            raise ValueError('timezone required')
        if not self.period_start < self.period_end <= self.period_start + timedelta(days=31):
            raise ValueError('report period must be between zero and 31 days')
        return self


def install_p1_routes(app, database: Database, analytics_client=None):
    def limits(conn, tenant_id):
        return conn.execute(
            "INSERT INTO platform.tenant_operating_limits(tenant_id) VALUES(%s) "
            "ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=excluded.tenant_id RETURNING *",
            (tenant_id,),
        ).fetchone()

    @app.get('/v1/platform/limits')
    def get_limits(request: Request, authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'operations.read')
            return limits(conn,principal.tenant_id)

    @app.put('/v1/platform/limits')
    def put_limits(body: OperatingLimitsInput, request: Request,
                   authorization: str | None = Header(None), if_match: int = Header(ge=1)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'operations.manage')
            limits(conn,principal.tenant_id)
            values = body.model_dump()
            assignments = ','.join(f'{key}=%s' for key in values)
            row = conn.execute(
                f"UPDATE platform.tenant_operating_limits SET {assignments},version=version+1,updated_at=clock_timestamp() "
                "WHERE tenant_id=%s AND version=%s RETURNING *",
                [*values.values(),principal.tenant_id,if_match],
            ).fetchone()
            if not row:
                raise HTTPException(409,'VERSION_CONFLICT')
            audit(conn,principal,request.state.correlation_id,'operations.limits.update',UUID(principal.tenant_id))
            return row

    @app.get('/v1/platform/usage')
    def usage(request: Request, authorization: str | None = Header(None),
              days: int = Query(30,ge=1,le=90)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'operations.read')
            return conn.execute(
                "SELECT usage_date,metric,amount FROM platform.usage_daily "
                "WHERE usage_date>=current_date-%s ORDER BY usage_date DESC,metric",(days-1,),
            ).fetchall()

    @app.get('/v1/integrations')
    def list_integrations(request: Request, authorization: str | None = Header(None),
                          after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'integration.read')
            rows = conn.execute(
                "SELECT tenant_id,id,workspace_id,integration_type,name,endpoint,enabled,configuration,version,created_at,"
                "secret_ref IS NOT NULL AS secret_configured FROM platform.integrations "
                "WHERE (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",(after,after,limit),
            ).fetchall()
            return rows

    @app.put('/v1/integrations/{integration_id}')
    def put_integration(integration_id: UUID, body: IntegrationInput, request: Request,
                        authorization: str | None = Header(None), if_match: int = Header(0,ge=0)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'integration.manage',str(body.workspace_id) if body.workspace_id else None)
            limits_row = limits(conn,principal.tenant_id)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(principal.tenant_id+':integrations',))
            existing = conn.execute('SELECT * FROM platform.integrations WHERE id=%s FOR UPDATE',(integration_id,)).fetchone()
            values = body.model_dump()
            if if_match == 0:
                if existing:
                    raise HTTPException(409,'VERSION_CONFLICT')
                count = conn.execute('SELECT count(*) AS n FROM platform.integrations').fetchone()['n']
                if count >= limits_row['max_integrations']:
                    raise HTTPException(429,'TENANT_QUOTA_EXCEEDED')
                row = conn.execute(
                    'INSERT INTO platform.integrations(tenant_id,id,workspace_id,integration_type,name,endpoint,secret_ref,enabled,configuration) '
                    'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *',
                    (principal.tenant_id,integration_id,body.workspace_id,body.integration_type,body.name,body.endpoint,
                     body.secret_ref,body.enabled,psycopg.types.json.Jsonb(body.configuration)),
                ).fetchone()
            else:
                if not existing:
                    raise HTTPException(404,'NOT_FOUND')
                if existing['workspace_id'] != body.workspace_id:
                    raise HTTPException(409,'PARENT_IMMUTABLE')
                row = conn.execute(
                    'UPDATE platform.integrations SET integration_type=%s,name=%s,endpoint=%s,secret_ref=%s,enabled=%s,configuration=%s,version=version+1 '
                    'WHERE id=%s AND version=%s RETURNING *',
                    (body.integration_type,body.name,body.endpoint,body.secret_ref,body.enabled,
                     psycopg.types.json.Jsonb(body.configuration),integration_id,if_match),
                ).fetchone()
                if not row:
                    raise HTTPException(409,'VERSION_CONFLICT')
            audit(conn,principal,request.state.correlation_id,'integration.write',integration_id)
            row = dict(row)
            row.pop('secret_ref',None)
            row['secret_configured'] = bool(body.secret_ref)
            return row

    @app.post('/v1/reports',status_code=202)
    def request_report(body: ReportInput, request: Request,
                       authorization: str | None = Header(None),
                       idempotency_key: str = Header(min_length=16,max_length=128)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'report.manage',str(body.workspace_id))
            limits_row = limits(conn,principal.tenant_id)
            workspace = conn.execute('SELECT id FROM platform.workspaces WHERE id=%s',(body.workspace_id,)).fetchone()
            if not workspace:
                raise HTTPException(404,'NOT_FOUND')
            if body.environment_id:
                env = conn.execute('SELECT workspace_id FROM platform.environments WHERE id=%s',(body.environment_id,)).fetchone()
                if not env or env['workspace_id'] != body.workspace_id:
                    raise HTTPException(404,'NOT_FOUND')
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(principal.tenant_id+':reports:'+idempotency_key,))
            existing = conn.execute("SELECT * FROM platform.jobs WHERE idempotency_key=%s",(idempotency_key,)).fetchone()
            if existing:
                report = conn.execute('SELECT * FROM platform.reports WHERE id=%s',(existing['id'],)).fetchone()
                if report:
                    return report
                raise HTTPException(409,'IDEMPOTENCY_CONFLICT')
            usage = conn.execute(
                "INSERT INTO platform.usage_daily(tenant_id,usage_date,metric,amount) VALUES(%s,current_date,'reports_requested',1) "
                "ON CONFLICT(tenant_id,usage_date,metric) DO UPDATE SET amount=platform.usage_daily.amount+1 RETURNING amount",
                (principal.tenant_id,),
            ).fetchone()['amount']
            if usage > limits_row['max_daily_reports']:
                raise HTTPException(429,'TENANT_QUOTA_EXCEEDED')
            report_id = uuid4()
            expires_at = datetime.now(timezone.utc)+timedelta(days=limits_row['report_retention_days'])
            row = conn.execute(
                'INSERT INTO platform.reports(tenant_id,id,workspace_id,environment_id,requested_by,report_type,output_format,period_start,period_end,expires_at) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *',
                (principal.tenant_id,report_id,body.workspace_id,body.environment_id,principal.identity_id,
                 body.report_type,body.output_format,body.period_start,body.period_end,expires_at),
            ).fetchone()
            payload={'report_id':str(report_id),'report_type':body.report_type,'output_format':body.output_format,
                     'period_start':body.period_start.isoformat(),'period_end':body.period_end.isoformat()}
            conn.execute(
                "INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,idempotency_key,max_attempts) "
                "VALUES(%s,%s,%s,%s,'report.generate','P4',%s,%s,5)",
                (principal.tenant_id,report_id,body.workspace_id,body.environment_id,
                 psycopg.types.json.Jsonb(payload),idempotency_key),
            )
            enqueue_event(conn,principal,namespace='billing',event_type='billing.usage.recorded',priority='P5',payload={
                'event_id':str(uuid4()),'metric':'reports_requested','quantity':1,
                'occurred_at':datetime.now(timezone.utc).isoformat()})
            audit(conn,principal,request.state.correlation_id,'report.request',report_id)
            return row

    @app.post('/v1/integrations/{integration_id}/test',status_code=202)
    def test_integration(integration_id: UUID, request: Request,
                         authorization: str | None = Header(None),
                         idempotency_key: str = Header(min_length=16,max_length=128)):
        with database.authenticated(authorization) as (conn, principal):
            integration=conn.execute('SELECT * FROM platform.integrations WHERE id=%s',(integration_id,)).fetchone()
            if not integration:
                raise HTTPException(404,'NOT_FOUND')
            database.authorize(principal,'integration.manage',str(integration['workspace_id']) if integration['workspace_id'] else None)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(principal.tenant_id+':delivery:'+idempotency_key,))
            existing=conn.execute('SELECT * FROM platform.jobs WHERE idempotency_key=%s',(idempotency_key,)).fetchone()
            if existing:
                delivery=conn.execute('SELECT * FROM platform.integration_deliveries WHERE id=%s',(existing['id'],)).fetchone()
                if delivery:
                    return delivery
                raise HTTPException(409,'IDEMPOTENCY_CONFLICT')
            delivery_id=uuid4(); event_id='test:'+idempotency_key
            payload={'event_type':'integration.test','event_id':event_id,'occurred_at':datetime.now(timezone.utc).isoformat()}
            row=conn.execute(
                'INSERT INTO platform.integration_deliveries(tenant_id,id,integration_id,event_id,payload) VALUES(%s,%s,%s,%s,%s) RETURNING *',
                (principal.tenant_id,delivery_id,integration_id,event_id,psycopg.types.json.Jsonb(payload)),
            ).fetchone()
            conn.execute(
                "INSERT INTO platform.jobs(tenant_id,id,workspace_id,job_type,priority,payload,idempotency_key,max_attempts) "
                "VALUES(%s,%s,%s,'integration.deliver','P4',%s,%s,8)",
                (principal.tenant_id,delivery_id,integration['workspace_id'],
                 psycopg.types.json.Jsonb({'delivery_id':str(delivery_id)}),idempotency_key),
            )
            audit(conn,principal,request.state.correlation_id,'integration.test',delivery_id)
            return row

    @app.get('/v1/reports')
    def reports(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'report.read',str(workspace_id))
            return conn.execute(
                'SELECT * FROM platform.reports WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s',
                (workspace_id,after,after,limit),
            ).fetchall()

    @app.get('/v1/analytics/runtime-summary')
    def runtime_summary(request: Request, workspace_id: UUID, period_start: datetime,
                        period_end: datetime, authorization: str | None = Header(None)):
        if period_start.tzinfo is None or period_end.tzinfo is None or not period_start < period_end <= period_start+timedelta(days=31):
            raise HTTPException(422,'INVALID_TIME_RANGE')
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,'analytics.read',str(workspace_id))
            if not conn.execute('SELECT id FROM platform.workspaces WHERE id=%s',(workspace_id,)).fetchone():
                raise HTTPException(404,'NOT_FOUND')
            if analytics_client is None:
                raise HTTPException(503,'ANALYTICS_UNAVAILABLE')
            return analytics_client.runtime_summary(principal.tenant_id,str(workspace_id),period_start,period_end)
