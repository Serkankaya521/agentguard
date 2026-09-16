"""P2 enterprise provisioning endpoints."""
from uuid import UUID,uuid5
from datetime import datetime,timedelta,timezone
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator

import psycopg
from fastapi import Header,HTTPException,Request,Response
from fastapi.responses import JSONResponse

from database import Database,audit
from scim import parse_user

class StrictModel(BaseModel):model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
class OIDCMappingInput(StrictModel):
    issuer:str=Field(max_length=2048);audience:str=Field(min_length=1,max_length=255);jwks_url:str=Field(max_length=2048)
    default_role:Literal['admin','editor','approver','reader']='reader';enabled:bool=True
    @model_validator(mode='after')
    def https_only(self):
        if not self.issuer.startswith('https://') or not self.jwks_url.startswith('https://'):raise ValueError('https required')
        return self
class ScheduleInput(StrictModel):
    workspace_id:UUID;environment_id:UUID|None=None
    report_type:Literal['findings','audit','runtime_summary'];output_format:Literal['json','csv','pdf']
    interval_minutes:Literal[60,1440,10080,43200];lookback_minutes:int=Field(ge=60,le=44640)
    enabled:bool=True;next_run_at:datetime


def _scim(row):
    return {'schemas':['urn:ietf:params:scim:schemas:core:2.0:User'],'id':str(row['id']),
            'externalId':row['external_subject'].removeprefix('scim:'),
            'userName':row['attributes'].get('user_name',row['display_name']),
            'displayName':row['display_name'],'active':row['status']=='active',
            'meta':{'resourceType':'User','version':str(row['version'])}}


def install_p2_routes(app,database:Database):
    @app.get('/v1/sso/oidc-mappings')
    def oidc_mappings(request:Request,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,'sso.manage');return conn.execute('SELECT * FROM platform.oidc_mappings ORDER BY id').fetchall()
    @app.put('/v1/sso/oidc-mappings/{mapping_id}')
    def put_oidc_mapping(mapping_id:UUID,body:OIDCMappingInput,request:Request,authorization:str|None=Header(None),if_match:int=Header(0,ge=0)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,'sso.manage');existing=conn.execute('SELECT * FROM platform.oidc_mappings WHERE id=%s FOR UPDATE',(mapping_id,)).fetchone()
            values=(body.issuer.rstrip('/'),body.audience,body.jwks_url,body.default_role,body.enabled)
            if if_match==0:
                if existing:raise HTTPException(409,'VERSION_CONFLICT')
                row=conn.execute('INSERT INTO platform.oidc_mappings(tenant_id,id,issuer,audience,jwks_url,default_role,enabled) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *',(principal.tenant_id,mapping_id,*values)).fetchone()
            else:
                row=conn.execute('UPDATE platform.oidc_mappings SET issuer=%s,audience=%s,jwks_url=%s,default_role=%s,enabled=%s,version=version+1 WHERE id=%s AND version=%s RETURNING *',(*values,mapping_id,if_match)).fetchone()
                if not row:raise HTTPException(409 if existing else 404,'VERSION_CONFLICT' if existing else 'NOT_FOUND')
            audit(conn,principal,request.state.correlation_id,'sso.mapping.write',mapping_id);return row

    @app.get('/v1/report-schedules')
    def schedules(request:Request,workspace_id:UUID,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,'report.read',str(workspace_id));return conn.execute('SELECT * FROM platform.report_schedules WHERE workspace_id=%s ORDER BY id',(workspace_id,)).fetchall()
    @app.put('/v1/report-schedules/{schedule_id}')
    def put_schedule(schedule_id:UUID,body:ScheduleInput,request:Request,authorization:str|None=Header(None),if_match:int=Header(0,ge=0)):
        if body.next_run_at.tzinfo is None:raise HTTPException(422,'TIMEZONE_REQUIRED')
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,'schedule.manage',str(body.workspace_id));
            if not conn.execute('SELECT id FROM platform.workspaces WHERE id=%s',(body.workspace_id,)).fetchone():raise HTTPException(404,'NOT_FOUND')
            existing=conn.execute('SELECT * FROM platform.report_schedules WHERE id=%s FOR UPDATE',(schedule_id,)).fetchone()
            values=(body.workspace_id,body.environment_id,body.report_type,body.output_format,body.interval_minutes,body.lookback_minutes,body.enabled,body.next_run_at)
            if if_match==0:
                if existing:raise HTTPException(409,'VERSION_CONFLICT')
                row=conn.execute('INSERT INTO platform.report_schedules(tenant_id,id,workspace_id,environment_id,created_by,report_type,output_format,interval_minutes,lookback_minutes,enabled,next_run_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *',(principal.tenant_id,schedule_id,body.workspace_id,body.environment_id,principal.identity_id,*values[2:])).fetchone()
            else:
                if existing and existing['workspace_id']!=body.workspace_id:raise HTTPException(409,'PARENT_IMMUTABLE')
                row=conn.execute('UPDATE platform.report_schedules SET environment_id=%s,report_type=%s,output_format=%s,interval_minutes=%s,lookback_minutes=%s,enabled=%s,next_run_at=%s,version=version+1 WHERE id=%s AND version=%s RETURNING *',(body.environment_id,*values[2:],schedule_id,if_match)).fetchone()
                if not row:raise HTTPException(409 if existing else 404,'VERSION_CONFLICT' if existing else 'NOT_FOUND')
            audit(conn,principal,request.state.correlation_id,'report.schedule.write',schedule_id);return row

    @app.get('/v1/billing/usage')
    def billing_usage(request:Request,authorization:str|None=Header(None),days:int=30):
        if not 1<=days<=366:raise HTTPException(422,'INVALID_RANGE')
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,'billing.read');return conn.execute('SELECT metric,sum(amount) AS amount FROM platform.usage_daily WHERE usage_date>=current_date-%s GROUP BY metric ORDER BY metric',(days-1,)).fetchall()
    @app.post('/scim/v2/Users')
    def provision_user(body:dict,request:Request,
                       authorization:str|None=Header(None)):
        try:user=parse_user(body)
        except ValueError as exc:raise HTTPException(422,'SCIM_INVALID_RESOURCE') from exc
        with database.authenticated(authorization) as (conn,principal):
            if principal.identity_type!='service':raise HTTPException(403,'SERVICE_IDENTITY_REQUIRED')
            database.authorize(principal,'identity.manage')
            subject='scim:'+user.external_id
            identity_id=uuid5(UUID(principal.tenant_id),subject)
            conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(principal.tenant_id+':'+subject,))
            existing=conn.execute('SELECT * FROM platform.identities WHERE external_subject=%s FOR UPDATE',(subject,)).fetchone()
            attributes=psycopg.types.json.Jsonb({'user_name':user.user_name,'provisioned_by':'scim'})
            if existing:
                row=conn.execute('UPDATE platform.identities SET display_name=%s,status=%s,attributes=%s,version=version+1 WHERE id=%s RETURNING *',
                    (user.display_name,'active' if user.active else 'suspended',attributes,existing['id'])).fetchone()
                status_code=200
            else:
                row=conn.execute('INSERT INTO platform.identities(tenant_id,id,identity_type,external_subject,display_name,status,attributes) VALUES(%s,%s,\'user\',%s,%s,%s,%s) RETURNING *',
                    (principal.tenant_id,identity_id,subject,user.display_name,'active' if user.active else 'suspended',attributes)).fetchone()
                status_code=201
            audit(conn,principal,request.state.correlation_id,'scim.user.provision',row['id'])
            return JSONResponse(_scim(row),status_code=status_code,media_type='application/scim+json')

    @app.get('/scim/v2/Users/{identity_id}')
    def get_user(identity_id:UUID,request:Request,
                 authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            if principal.identity_type!='service':raise HTTPException(403,'SERVICE_IDENTITY_REQUIRED')
            database.authorize(principal,'identity.manage')
            row=conn.execute("SELECT * FROM platform.identities WHERE id=%s AND external_subject LIKE 'scim:%%'",(identity_id,)).fetchone()
            if not row:raise HTTPException(404,'NOT_FOUND')
            return JSONResponse(_scim(row),media_type='application/scim+json')

    @app.delete('/scim/v2/Users/{identity_id}',status_code=204)
    def deactivate_user(identity_id:UUID,request:Request,authorization:str|None=Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            if principal.identity_type!='service':raise HTTPException(403,'SERVICE_IDENTITY_REQUIRED')
            database.authorize(principal,'identity.manage')
            row=conn.execute("UPDATE platform.identities SET status='suspended',version=version+1 WHERE id=%s AND external_subject LIKE 'scim:%%' RETURNING id",(identity_id,)).fetchone()
            if not row:raise HTTPException(404,'NOT_FOUND')
            conn.execute('UPDATE platform.credentials SET revoked=true WHERE identity_id=%s',(identity_id,))
            audit(conn,principal,request.state.correlation_id,'scim.user.deactivate',identity_id)
            return Response(status_code=204)
