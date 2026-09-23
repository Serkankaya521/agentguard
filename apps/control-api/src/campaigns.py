"""Continuous adversarial campaign control-plane routes."""
from datetime import datetime,timezone
import re
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID,uuid4

import psycopg
from fastapi import Header,HTTPException,Request
from pydantic import BaseModel,ConfigDict,Field,model_validator

from database import Database,audit

SECRET_REF=re.compile(r'^env://[A-Z][A-Z0-9_]{1,127}$')

def _valid_api_base(value: str) -> bool:
    """Allow TLS endpoints and exact local-loopback HTTP origins only."""
    try:
        parsed=urlsplit(value)
        if parsed.username or parsed.password or not parsed.hostname:
            return False
        if parsed.scheme=='https':
            return True
        return parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1'}
    except ValueError:
        return False

class StrictModel(BaseModel):model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
class CampaignStatusInput(StrictModel):status:Literal['active','paused','archived']
class CampaignInput(StrictModel):
    workspace_id:UUID;environment_id:UUID
    name:str=Field(min_length=1,max_length=120)
    target_type:Literal['openai_compatible']='openai_compatible'
    target_config:dict[str,object]
    secret_ref:str|None=Field(None,max_length=512)
    canary_secret_ref:str|None=Field(None,max_length=512)
    seed_prompt:str=Field(min_length=1,max_length=16384)
    objective_markers:list[str]=Field(min_length=1,max_length=20)
    request_budget:int=Field(ge=2,le=10000)
    mutation_budget:int=Field(ge=1,le=100000)
    max_concurrency:int=Field(ge=1,le=32)
    interval_minutes:int|None=Field(None,ge=1,le=10080)
    status:Literal['active','paused','archived']='paused'
    next_run_at:datetime|None=None
    @model_validator(mode='after')
    def secure(self):
        if self.status=='active' and (not self.interval_minutes or not self.next_run_at):raise ValueError('active campaign requires schedule')
        if self.next_run_at and self.next_run_at.tzinfo is None:raise ValueError('timezone required')
        for ref in (self.secret_ref,self.canary_secret_ref):
            if ref and not SECRET_REF.fullmatch(ref):raise ValueError('invalid secret reference')
        if {'api_key','token','secret','password','credential'}&{k.lower() for k in self.target_config}:raise ValueError('plaintext secrets forbidden')
        if self.mutation_budget < self.request_budget:raise ValueError('mutation_budget must cover request_budget')
        if self.max_concurrency != 1:raise ValueError('this adapter supports max_concurrency=1')
        endpoint=str(self.target_config.get('api_base',''))
        if self.target_type=='openai_compatible' and not _valid_api_base(endpoint):raise ValueError('secure api_base required')
        return self

def public(row):
    data=dict(row);data.pop('secret_ref',None);data.pop('canary_secret_ref',None)
    data['secret_configured']=bool(row.get('secret_ref'));data['canary_configured']=bool(row.get('canary_secret_ref'));return data

def install_campaign_routes(app,database:Database,secret_allowlist:dict[str,set[str]]|None=None):
    allowed_by_tenant=secret_allowlist or {}

    def authorize_secrets(tenant_id,body):
        requested={ref[6:] for ref in (body.secret_ref,body.canary_secret_ref) if ref}
        if requested and not requested.issubset(allowed_by_tenant.get(str(tenant_id),set())):
            raise HTTPException(403,'SECRET_NOT_ASSIGNED')
    @app.get('/v1/campaigns')
    def list_campaigns(request:Request,workspace_id:UUID,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,p):
            database.authorize(p,'tenant.read',str(workspace_id));return [public(r) for r in conn.execute('SELECT * FROM platform.campaigns WHERE workspace_id=%s ORDER BY created_at DESC LIMIT 100',(workspace_id,)).fetchall()]

    @app.get('/v1/campaigns/{campaign_id}')
    def get_campaign(campaign_id:UUID,request:Request,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,p):
            row=conn.execute('SELECT * FROM platform.campaigns WHERE id=%s',(campaign_id,)).fetchone()
            if not row:raise HTTPException(404,'NOT_FOUND')
            database.authorize(p,'tenant.read',str(row['workspace_id']));return public(row)

    @app.put('/v1/campaigns/{campaign_id}')
    def put_campaign(campaign_id:UUID,body:CampaignInput,request:Request,authorization:str|None=Header(None),if_match:int=Header(0,ge=0)):
        with database.authenticated(authorization) as (conn,p):
            database.authorize(p,'campaign.manage',str(body.workspace_id))
            authorize_secrets(p.tenant_id,body)
            env=conn.execute('SELECT workspace_id,kind FROM platform.environments WHERE id=%s',(body.environment_id,)).fetchone()
            if not env or env['workspace_id']!=body.workspace_id:raise HTTPException(404,'NOT_FOUND')
            database.authorize(p,'campaign.manage',str(body.workspace_id),env['kind'])
            existing=conn.execute('SELECT * FROM platform.campaigns WHERE id=%s FOR UPDATE',(campaign_id,)).fetchone()
            values=(body.name,body.target_type,psycopg.types.json.Jsonb(body.target_config),body.secret_ref,body.canary_secret_ref,body.seed_prompt,psycopg.types.json.Jsonb(body.objective_markers),body.request_budget,body.mutation_budget,body.max_concurrency,body.interval_minutes,body.status,body.next_run_at)
            if if_match==0:
                if existing:raise HTTPException(409,'VERSION_CONFLICT')
                conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(p.tenant_id+':campaigns',))
                campaign_limit=conn.execute(
                    'INSERT INTO platform.tenant_operating_limits(tenant_id) VALUES(%s) '
                    'ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=excluded.tenant_id RETURNING max_campaigns',
                    (p.tenant_id,)).fetchone()['max_campaigns']
                if conn.execute('SELECT count(*) AS n FROM platform.campaigns').fetchone()['n']>=campaign_limit:
                    raise HTTPException(429,'TENANT_QUOTA_EXCEEDED')
                row=conn.execute('INSERT INTO platform.campaigns(tenant_id,id,workspace_id,environment_id,created_by,name,target_type,target_config,secret_ref,canary_secret_ref,seed_prompt,objective_markers,request_budget,mutation_budget,max_concurrency,interval_minutes,status,next_run_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *',(p.tenant_id,campaign_id,body.workspace_id,body.environment_id,p.identity_id,*values)).fetchone()
            else:
                if existing and (existing['workspace_id']!=body.workspace_id or existing['environment_id']!=body.environment_id):raise HTTPException(409,'PARENT_IMMUTABLE')
                row=conn.execute('UPDATE platform.campaigns SET name=%s,target_type=%s,target_config=%s,secret_ref=%s,canary_secret_ref=%s,seed_prompt=%s,objective_markers=%s,request_budget=%s,mutation_budget=%s,max_concurrency=%s,interval_minutes=%s,status=%s,next_run_at=%s,version=version+1,updated_at=clock_timestamp() WHERE id=%s AND version=%s RETURNING *',(*values,campaign_id,if_match)).fetchone()
                if not row:raise HTTPException(409 if existing else 404,'VERSION_CONFLICT' if existing else 'NOT_FOUND')
            audit(conn,p,request.state.correlation_id,'campaign.write',campaign_id);return public(row)

    @app.post('/v1/campaigns/{campaign_id}/status')
    def set_campaign_status(campaign_id:UUID,body:CampaignStatusInput,request:Request,authorization:str|None=Header(None),if_match:int=Header(ge=1)):
        with database.authenticated(authorization) as (conn,p):
            campaign=conn.execute('SELECT * FROM platform.campaigns WHERE id=%s FOR UPDATE',(campaign_id,)).fetchone()
            if not campaign:raise HTTPException(404,'NOT_FOUND')
            env=conn.execute('SELECT kind FROM platform.environments WHERE id=%s',(campaign['environment_id'],)).fetchone()
            database.authorize(p,'campaign.manage',str(campaign['workspace_id']),env['kind'])
            if body.status=='active' and (not campaign['interval_minutes'] or not campaign['next_run_at']):raise HTTPException(409,'SCHEDULE_REQUIRED')
            row=conn.execute('UPDATE platform.campaigns SET status=%s,version=version+1,updated_at=clock_timestamp() WHERE id=%s AND version=%s RETURNING *',(body.status,campaign_id,if_match)).fetchone()
            if not row:raise HTTPException(409,'VERSION_CONFLICT')
            audit(conn,p,request.state.correlation_id,'campaign.status',campaign_id);return public(row)

    @app.post('/v1/campaigns/{campaign_id}/runs',status_code=202)
    def run_now(campaign_id:UUID,request:Request,authorization:str|None=Header(None),idempotency_key:str=Header(min_length=8,max_length=255)):
        with database.authenticated(authorization) as (conn,p):
            campaign=conn.execute('SELECT * FROM platform.campaigns WHERE id=%s',(campaign_id,)).fetchone()
            if not campaign:raise HTTPException(404,'NOT_FOUND')
            env=conn.execute('SELECT kind FROM platform.environments WHERE id=%s',(campaign['environment_id'],)).fetchone()
            database.authorize(p,'campaign.manage',str(campaign['workspace_id']),env['kind'])
            existing=conn.execute("SELECT id,payload->>'run_id' AS run_id FROM platform.jobs WHERE idempotency_key=%s",(idempotency_key,)).fetchone()
            if existing:return {'run_id':existing['run_id'],'status':'queued'}
            run_id=uuid4();job_id=uuid4();now=datetime.now(timezone.utc)
            conn.execute('INSERT INTO platform.campaign_runs(tenant_id,id,campaign_id,scheduled_for) VALUES(%s,%s,%s,%s)',(p.tenant_id,run_id,campaign_id,now))
            payload={'campaign_id':str(campaign_id),'run_id':str(run_id)}
            conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,max_attempts,idempotency_key) VALUES(%s,%s,%s,%s,'red_team.execute','P3',%s,5,%s)",(p.tenant_id,job_id,campaign['workspace_id'],campaign['environment_id'],psycopg.types.json.Jsonb(payload),idempotency_key))
            audit(conn,p,request.state.correlation_id,'campaign.run.request',run_id);return {'run_id':str(run_id),'status':'queued'}

    @app.get('/v1/campaigns/{campaign_id}/runs')
    def list_runs(campaign_id:UUID,request:Request,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,p):
            campaign=conn.execute('SELECT workspace_id FROM platform.campaigns WHERE id=%s',(campaign_id,)).fetchone()
            if not campaign:raise HTTPException(404,'NOT_FOUND')
            database.authorize(p,'tenant.read',str(campaign['workspace_id']));return conn.execute('SELECT * FROM platform.campaign_runs WHERE campaign_id=%s ORDER BY created_at DESC LIMIT 100',(campaign_id,)).fetchall()

    @app.get('/v1/regression-cases')
    def regression_cases(request:Request,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,p):
            database.authorize(p,'tenant.read');return conn.execute('SELECT id,finding_id,campaign_id,expected_block,status,last_run_at,created_at FROM platform.regression_cases ORDER BY created_at DESC LIMIT 100').fetchall()

    @app.post('/v1/regression-cases/{case_id}/runs',status_code=202)
    def run_regression(case_id:UUID,request:Request,authorization:str|None=Header(None),idempotency_key:str=Header(min_length=8,max_length=255)):
        with database.authenticated(authorization) as (conn,p):
            case=conn.execute('SELECT r.*,c.workspace_id,c.environment_id FROM platform.regression_cases r JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id WHERE r.id=%s',(case_id,)).fetchone()
            if not case:raise HTTPException(404,'NOT_FOUND')
            env=conn.execute('SELECT kind FROM platform.environments WHERE id=%s',(case['environment_id'],)).fetchone()
            database.authorize(p,'campaign.manage',str(case['workspace_id']),env['kind'])
            existing=conn.execute('SELECT id FROM platform.jobs WHERE idempotency_key=%s',(idempotency_key,)).fetchone()
            if existing:return {'case_id':str(case_id),'status':'queued'}
            payload={'case_id':str(case_id),'campaign_id':str(case['campaign_id'])}
            conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,max_attempts,idempotency_key) VALUES(%s,%s,%s,%s,'regression.execute','P3',%s,5,%s)",(p.tenant_id,uuid4(),case['workspace_id'],case['environment_id'],psycopg.types.json.Jsonb(payload),idempotency_key))
            audit(conn,p,request.state.correlation_id,'regression.run.request',case_id);return {'case_id':str(case_id),'status':'queued'}
