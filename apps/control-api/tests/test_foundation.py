"""Run against a disposable PostgreSQL database, never customer infrastructure."""
import hashlib
import importlib.util
import os
import sys
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'apps/control-api/src'))
from foundation import create_app
spec = importlib.util.spec_from_file_location('b1_migrate', ROOT / 'migrations/postgresql/migrate.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class SecretDSN(str):
    def __repr__(self):
        return '<redacted-dsn>'


def test_unauthenticated_and_payload_validation():
    with TestClient(create_app('host=127.0.0.1 port=1 dbname=unused')) as client:
        assert client.get('/v1/organizations').status_code == 401
        r = client.put('/v1/workspaces/'+str(uuid4()), json={'name':'x','tenant_id':'spoof'})
        assert r.status_code == 422 and 'spoof' not in r.text
        r = client.put('/v1/workspaces/'+str(uuid4()), content=b'x'*4097)
        assert r.status_code == 413 and r.headers['X-Correlation-ID']
        assert client.get('/v1/workspaces?limit=101').status_code == 422
        assert client.get('/v1/workspaces?limit=0').status_code == 422


def test_database_failure_is_sanitized():
    with TestClient(create_app('host=127.0.0.1 port=1 dbname=unused connect_timeout=1')) as client:
        r = client.get('/v1/workspaces', headers={'Authorization':'Bearer '+'x'*40})
        assert r.status_code == 503
        assert r.json()['code'] in ('DATABASE_UNAVAILABLE','DATABASE_BUSY')
        assert 'dbname' not in r.text


@pytest.fixture(scope='module')
def db():
    owner = SecretDSN(os.environ.get('B1_TEST_OWNER_DSN',''))
    app = SecretDSN(os.environ.get('B1_TEST_APP_DSN',''))
    if not owner or not app:
        pytest.skip('Set B1_TEST_OWNER_DSN and B1_TEST_APP_DSN to a disposable database')
    with psycopg.connect(owner) as conn:
        assert conn.execute("SELECT to_regnamespace('platform')").fetchone()[0] is None, 'Requires empty disposable database'
    migration.migrate(owner,'up')
    migration.migrate(owner,'up')
    migration.migrate(owner,'down')
    migration.migrate(owner,'up')
    tenants = [uuid4(),uuid4()]
    tokens = {}
    with psycopg.connect(owner) as conn:
        for index, tenant in enumerate(tenants):
            for role in ['admin','reader']:
                token = str(uuid4())+str(uuid4())
                tokens[index,role] = token
                conn.execute("INSERT INTO platform.credentials(token_hash,tenant_id,identity_id,role,expires_at) VALUES(%s,%s,%s,%s,now()+interval '1 hour')",
                             (hashlib.sha256(token.encode()).hexdigest(),tenant,uuid4(),role))
    def headers(index=0, role='admin', version=0):
        return {'Authorization':'Bearer '+tokens[index,role], 'If-Match':str(version)}
    with TestClient(create_app(app)) as client:
        for i,tenant in enumerate(tenants):
            assert client.put('/v1/organizations/'+str(tenant),json={'name':'organization'},headers=headers(i)).status_code == 200
        yield client,owner,app,tenants,headers,tokens


def test_hierarchy_crud_isolation_and_audit(db):
    client,owner,app,tenants,h,tokens = db
    ws, env = uuid4(),uuid4()
    wp, ep = '/v1/workspaces/'+str(ws), '/v1/environments/'+str(env)
    assert client.put(wp,json={'name':str(ws)},headers=h()).status_code == 200
    body = {'name':'test','workspace_id':str(ws),'kind':'test'}
    assert client.put(ep,json=body,headers=h()).status_code == 200
    assert client.put(ep,json=body,headers=h()).status_code == 200
    for path in [wp,ep,'/v1/organizations/'+str(tenants[0])]:
        assert client.get(path,headers=h(1)).status_code == 404
        assert client.delete(path,headers=h(1,version=1)).status_code == 404
    assert client.put(wp,json={'name':'evil'},headers=h(1,version=1)).status_code == 404
    assert client.put('/v1/environments/'+str(uuid4()),json=body,headers=h(1)).status_code == 404
    assert client.put(wp,json={'name':'reader'},headers=h(role='reader',version=1)).status_code == 403
    assert client.delete(ep,headers=h(role='reader',version=1)).status_code == 403
    assert client.get(ep,headers=h(role='reader')).status_code == 200
    assert client.get('/v1/environments',headers=h(1)).json() == []
    assert client.put(wp,json={'name':'updated'},headers=h(version=1)).status_code == 200
    assert client.put(wp,json={'name':'stale'},headers=h(version=1)).status_code == 409
    assert client.delete(wp,headers=h(version=2)).status_code == 409 # children block deletion
    assert client.delete(ep,headers=h(version=1)).status_code == 200
    assert client.delete(wp,headers=h(version=2)).status_code == 200
    with psycopg.connect(owner) as conn:
        assert conn.execute('SELECT count(*) FROM platform.audit WHERE tenant_id=%s AND resource_id=%s',(tenants[0],env)).fetchone()[0] == 2
    with pytest.raises(psycopg.Error):
        migration.migrate(owner,'down') # preserves audit/data


def test_direct_rls_constraints_and_audit(db):
    client,owner,app,tenants,h,tokens = db
    with psycopg.connect(app) as conn:
        assert conn.execute('SELECT * FROM platform.organizations').fetchall() == []
        conn.execute("SELECT set_config('app.tenant_id',%s,true)",(str(tenants[1]),))
        assert len(conn.execute('SELECT * FROM platform.organizations').fetchall()) == 1
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute('INSERT INTO platform.workspaces(tenant_id,id,name) VALUES(%s,%s,%s)',(tenants[0],uuid4(),'evil'))
    ws = uuid4()
    assert client.put('/v1/workspaces/'+str(ws),json={'name':str(ws)},headers=h()).status_code == 200
    with psycopg.connect(app) as conn:
        conn.execute("SELECT set_config('app.tenant_id',%s,true)",(str(tenants[1]),))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute("INSERT INTO platform.environments(tenant_id,id,workspace_id,name,kind) VALUES(%s,%s,%s,'x','test')",(tenants[1],uuid4(),ws))
    for sql in ['UPDATE platform.audit SET action=\'evil\'', 'DELETE FROM platform.audit', 'TRUNCATE platform.audit']:
        with psycopg.connect(app) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
    with TestClient(create_app(owner)) as unsafe:
        assert unsafe.get('/v1/organizations',headers=h()).json()['code'] == 'UNSAFE_DATABASE_ROLE'


def test_expiry_revocation_and_concurrent_writes(db):
    client,owner,app,tenants,h,tokens = db
    token = str(uuid4())+str(uuid4())
    with psycopg.connect(owner) as conn:
        conn.execute("INSERT INTO platform.credentials VALUES(%s,%s,%s,'admin',now()-interval '1 second',false)",
                     (hashlib.sha256(token.encode()).hexdigest(),tenants[0],uuid4()))
    assert client.get('/v1/organizations',headers={'Authorization':'Bearer '+token}).status_code == 401
    with psycopg.connect(owner) as conn:
        conn.execute("UPDATE platform.credentials SET revoked=true,expires_at=now()+interval '1 hour' WHERE token_hash=%s",(hashlib.sha256(token.encode()).hexdigest(),))
    assert client.get('/v1/organizations',headers={'Authorization':'Bearer '+token}).status_code == 401
    path = '/v1/workspaces/'+str(uuid4())
    def put(version):
        return client.put(path,json={'name':path},headers=h(version=version)).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(put,[0,0])) == [200,200]
        assert sorted(pool.map(put,[1,1])) == [200,409]


def test_audit_failure_rolls_back_mutation(db):
    client,owner,app,tenants,h,tokens = db
    resource = uuid4()
    with psycopg.connect(owner) as conn:
        conn.execute('REVOKE INSERT ON platform.audit FROM ag_control')
    try:
        assert client.put('/v1/workspaces/'+str(resource),json={'name':str(resource)},headers=h()).status_code == 503
        assert client.get('/v1/workspaces/'+str(resource),headers=h()).status_code == 404
    finally:
        with psycopg.connect(owner) as conn:
            conn.execute('GRANT INSERT ON platform.audit TO ag_control')
