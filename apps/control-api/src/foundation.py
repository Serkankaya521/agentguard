"""B1 Control API. Tenancy administration only; no runtime security decisions."""
import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager, contextmanager, nullcontext
from typing import Literal
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from psycopg_pool import PoolTimeout

log = logging.getLogger('agentguard.control')

class NameInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)

class EnvironmentInput(NameInput):
    workspace_id: UUID
    kind: Literal['production','staging','development','test']

class Entity(BaseModel):
    tenant_id: UUID
    id: UUID
    name: str
    version: int

class Environment(Entity):
    workspace_id: UUID
    kind: Literal['production','staging','development','test']

class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > 4096:
                cid = str(uuid4())
                response = JSONResponse(status_code=413, content={'code':'PAYLOAD_TOO_LARGE','correlation_id':cid}, headers={'X-Correlation-ID':cid})
                return await response(scope, receive, send)
            chunks.append(message.get('body', b''))
            if not message.get('more_body', False):
                break
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type':'http.request','body':b''.join(chunks),'more_body':False}
            return await receive()
        await self.app(scope, bounded_receive, send)


def create_app(dsn=None, *, policy_signing_key=None, approval_signing_key=None,
               evidence_signing_key=None, object_store=None, analytics_client=None,
               campaign_secret_allowlist=None,campaign_target_allowlist=None):
    database_url = dsn or os.environ['CONTROL_DATABASE_URL']
    from database import Database
    platform_database = Database(database_url)
    if object_store is None and os.environ.get('EVIDENCE_S3_ENDPOINT') and os.environ.get('EVIDENCE_S3_BUCKET'):
        from object_store import S3ObjectStore
        object_store = S3ObjectStore(endpoint_url=os.environ['EVIDENCE_S3_ENDPOINT'],
                                     bucket=os.environ['EVIDENCE_S3_BUCKET'],
                                     region=os.environ.get('EVIDENCE_S3_REGION','us-east-1'))
    telemetry = None
    if os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT'):
        from tracing import configure
        from metrics import PlatformMetrics
        configured = configure('agentguard-control-api',os.environ['OTEL_EXPORTER_OTLP_ENDPOINT'])
        telemetry = (configured.tracer,PlatformMetrics(configured.meter))
    if analytics_client is None and os.environ.get('CLICKHOUSE_ENDPOINT'):
        from analytics import ClickHouseAnalytics
        analytics_client=ClickHouseAnalytics(os.environ['CLICKHOUSE_ENDPOINT'],
            database=os.environ.get('CLICKHOUSE_DATABASE','agentguard'),
            user=os.environ.get('CLICKHOUSE_USER','agentguard'),
            password=os.environ.get('CLICKHOUSE_PASSWORD',''))
    @asynccontextmanager
    async def lifespan(application):
        yield
        platform_database.close()
    app = FastAPI(title='AgentGuard Control API', version='1.0.0', lifespan=lifespan)

    @app.get('/health/live')
    def live():
        return {'status':'ok'}

    @app.get('/health/ready')
    def ready():
        with platform_database.connect() as conn:
            versions = conn.execute('SELECT version FROM public.platform_migrations ORDER BY version').fetchall()
            if [row['version'] for row in versions] != [1,2,3,4,5,6,7]:
                raise HTTPException(503,'MIGRATION_REQUIRED')
        return {'status':'ready','migration':7}

    @app.middleware('http')
    async def metadata(request: Request, call_next):
        from database import bind_request
        request.state.correlation_id = uuid4()
        started = time.monotonic()
        span_context = telemetry[0].start_as_current_span('control.request') if telemetry else nullcontext()
        with bind_request(request), span_context as span:
            response = await call_next(request)
            if telemetry:
                attrs = telemetry[1].attributes(operation=request.method,status=str(response.status_code))
                telemetry[1].requests.add(1,attrs)
                telemetry[1].latency.record((time.monotonic()-started)*1000,attrs)
                span.set_attribute('http.response.status_code',response.status_code)
        response.headers['X-Correlation-ID'] = str(request.state.correlation_id)
        log.info('control_request correlation_id=%s status=%s duration_ms=%.2f',
                 request.state.correlation_id, response.status_code, (time.monotonic()-started)*1000)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if exc.status_code == 403:
            principal = getattr(request.state, 'auth_principal', None)
            if principal is not None:
                await run_in_threadpool(
                    platform_database.audit_authorization_denial,
                    principal, request.state.correlation_id)
        return JSONResponse(status_code=exc.status_code, content={
            'code':exc.detail, 'correlation_id':str(request.state.correlation_id)})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return await http_error(request, HTTPException(422, 'INVALID_INPUT'))

    @app.exception_handler(psycopg.Error)
    async def database_error(request, exc):
        conflict = isinstance(exc, psycopg.IntegrityError)
        return await http_error(request, HTTPException(409 if conflict else 503,
                                'CONFLICT' if conflict else 'DATABASE_UNAVAILABLE'))

    @app.exception_handler(PoolTimeout)
    async def pool_error(request, exc):
        return await http_error(request, HTTPException(503, 'DATABASE_BUSY'))

    @contextmanager
    def session(request, authorization, write=False):
        with platform_database.authenticated(authorization) as (conn, principal):
            platform_database.authorize(principal, 'tenant.write' if write else 'tenant.read')
            yield conn, {'tenant_id': principal.tenant_id,
                         'identity_id': principal.identity_id,
                         'role': principal.role_for(None)}

    def get(conn, table, resource_id):
        row = conn.execute(f'SELECT * FROM platform.{table} WHERE id=%s', (resource_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'NOT_FOUND')
        return row

    def audit(conn, p, request, action, resource_id):
        conn.execute('INSERT INTO platform.audit (tenant_id,identity_id,correlation_id,action,resource_id) VALUES (%s,%s,%s,%s,%s)',
                     (p['tenant_id'],p['identity_id'],request.state.correlation_id,action,resource_id))

    def register(table, input_model, output_model):
        # Table and column identifiers below are internal constants, never payloads.
        def put(resource_id: UUID, body: input_model, request: Request,
                authorization: str | None = Header(default=None),
                if_match: int = Header(default=0, ge=0)):
            with session(request, authorization, True) as (conn, p):
                if table == 'organizations' and str(resource_id) != str(p['tenant_id']):
                    raise HTTPException(404, 'NOT_FOUND')
                values = body.model_dump()
                if table == 'environments':
                    get(conn, 'workspaces', values['workspace_id'])
                # Serialize same resource writes for idempotent create/retry.
                conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                             (str(p['tenant_id']) + ':' + table + ':' + str(resource_id),))
                existing = conn.execute(f'SELECT * FROM platform.{table} WHERE id=%s', (resource_id,)).fetchone()
                if if_match == 0:
                    if existing:
                        if existing['version'] == 1 and all(existing[k] == v for k,v in values.items()):
                            return existing
                        raise HTTPException(409, 'VERSION_CONFLICT')
                    cols = ['tenant_id','id',*values]
                    row = conn.execute(f'INSERT INTO platform.{table} ({",".join(cols)}) VALUES ({",".join(["%s"]*len(cols))}) RETURNING *',
                                       [p['tenant_id'],resource_id,*values.values()]).fetchone()
                else:
                    if not existing:
                        raise HTTPException(404, 'NOT_FOUND')
                    if table == 'environments' and existing['workspace_id'] != values['workspace_id']:
                        raise HTTPException(409, 'PARENT_IMMUTABLE')
                    assignments = ','.join(k+'=%s' for k in values)
                    row = conn.execute(f'UPDATE platform.{table} SET {assignments},version=version+1 WHERE id=%s AND version=%s RETURNING *',
                                       [*values.values(),resource_id,if_match]).fetchone()
                    if not row:
                        raise HTTPException(409, 'VERSION_CONFLICT')
                audit(conn,p,request,table+'.write',resource_id)
                return row

        def read(resource_id: UUID, request: Request, authorization: str | None = Header(default=None)):
            with session(request,authorization) as (conn,p):
                return get(conn,table,resource_id)

        def listing(request: Request, authorization: str | None = Header(default=None),
                    limit: int = Query(50,ge=1,le=100), after: UUID | None = None):
            with session(request,authorization) as (conn,p):
                return conn.execute(f'SELECT * FROM platform.{table} WHERE (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s',
                                    (after,after,limit)).fetchall()

        def delete(resource_id: UUID, request: Request, if_match: int = Header(ge=1),
                   authorization: str | None = Header(default=None)):
            with session(request,authorization,True) as (conn,p):
                get(conn,table,resource_id)
                row = conn.execute(f'DELETE FROM platform.{table} WHERE id=%s AND version=%s RETURNING id',
                                   (resource_id,if_match)).fetchone()
                if not row:
                    raise HTTPException(409, 'VERSION_CONFLICT')
                audit(conn,p,request,table+'.delete',resource_id)
                return {'deleted':True}

        path = '/v1/' + table
        app.add_api_route(path,listing,methods=['GET'],response_model=list[output_model],name=table+'_list')
        app.add_api_route(path+'/{resource_id}',put,methods=['PUT'],response_model=output_model,name=table+'_put')
        app.add_api_route(path+'/{resource_id}',read,methods=['GET'],response_model=output_model,name=table+'_get')
        app.add_api_route(path+'/{resource_id}',delete,methods=['DELETE'],response_model=dict[str,bool],name=table+'_delete')

    register('organizations',NameInput,Entity)
    register('workspaces',NameInput,Entity)
    register('environments',EnvironmentInput,Environment)
    from enterprise import install_enterprise_routes
    install_enterprise_routes(
        app,
        platform_database,
        policy_signing_key=(policy_signing_key or os.environ.get('POLICY_SIGNING_KEY')),
        approval_signing_key=(approval_signing_key or os.environ.get('APPROVAL_SIGNING_KEY')),
        evidence_signing_key=(evidence_signing_key or os.environ.get('EVIDENCE_SIGNING_KEY')),
        object_store=object_store,
    )
    from p1_operations import install_p1_routes
    install_p1_routes(app, platform_database, analytics_client)
    from p2_enterprise import install_p2_routes
    install_p2_routes(app, platform_database)
    from campaigns import install_campaign_routes
    if campaign_secret_allowlist is None:
        raw=os.environ.get('CAMPAIGN_SECRET_ALLOWLIST_JSON','{}')
        try:
            campaign_secret_allowlist={str(k):set(v) for k,v in json.loads(raw).items()}
        except (TypeError,ValueError):
            raise RuntimeError('invalid CAMPAIGN_SECRET_ALLOWLIST_JSON')
    if campaign_target_allowlist is None:
        raw=os.environ.get('CAMPAIGN_TARGET_ALLOWLIST_JSON','{}')
        try:
            campaign_target_allowlist={str(k):set(v) for k,v in json.loads(raw).items()}
        except (TypeError,ValueError):
            raise RuntimeError('invalid CAMPAIGN_TARGET_ALLOWLIST_JSON')
    install_campaign_routes(app, platform_database, campaign_secret_allowlist,
                            campaign_target_allowlist)
    from assessments import install_assessment_routes
    install_assessment_routes(app, platform_database)
    from runtime_guard import install_runtime_guard_routes
    install_runtime_guard_routes(app, platform_database)
    app.add_middleware(BodyLimit)
    return app
