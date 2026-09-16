"""Durable event and job failure behavior against disposable PostgreSQL."""
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import sys
from uuid import uuid4

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'apps/control-api/src'),str(ROOT/'apps/worker/src')]
from event_backbone import OutboxPublisher
from queues.repository import JobRepository
from queues.backpressure import QueueLimits, admitted
from platform_cache import cache_key
from audit import verify_links
from performance import percentiles, runtime_slo_passes

spec = importlib.util.spec_from_file_location('event_migrate',ROOT/'migrations/postgresql/migrate.py')
migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)


class SecretDSN(str):
    def __repr__(self):
        return '<redacted-dsn>'


class Producer:
    def __init__(self, fail=False): self.fail, self.records = fail, []
    def publish(self, topic, **record):
        if self.fail: raise TimeoutError('secret payload must not be persisted')
        self.records.append((topic,record))


@pytest.fixture(scope='module')
def event_db():
    owner = SecretDSN(os.environ.get('B1_TEST_OWNER_DSN',''))
    app = SecretDSN(os.environ.get('B1_TEST_APP_DSN',''))
    if not owner or not app: pytest.skip('Disposable PostgreSQL DSNs are required')
    migration.migrate(owner,'up')
    tenant = uuid4()
    with psycopg.connect(owner) as conn:
        conn.execute("INSERT INTO platform.organizations VALUES(%s,%s,'events',1)",(tenant,tenant))
    return owner,app,tenant


def insert_event(owner,tenant,event_id,priority='P3',payload=None):
    payload = payload or {'event_id':str(event_id),'value':'safe'}
    with psycopg.connect(owner) as conn:
        seq = conn.execute("INSERT INTO platform.event_sequences VALUES(%s,'test',0) ON CONFLICT(tenant_id,namespace) DO UPDATE SET sequence=platform.event_sequences.sequence+1 RETURNING sequence",(tenant,)).fetchone()[0]
        conn.execute("INSERT INTO platform.outbox(tenant_id,id,namespace,sequence,event_type,priority,payload) VALUES(%s,%s,'test',%s,'test.event',%s,%s)",
                     (tenant,event_id,seq,priority,psycopg.types.json.Jsonb(payload)))


def test_outbox_priority_retry_dlq_and_replay(event_db):
    owner,app,tenant = event_db
    ids = [uuid4(),uuid4()]
    insert_event(owner,tenant,ids[0],'P5'); insert_event(owner,tenant,ids[1],'P2')
    producer = Producer()
    result = OutboxPublisher(app,producer,batch_size=10).deliver_once(tenant)
    assert result.published == 2
    assert [r[1]['headers'][1][1] for r in producer.records] == [b'P2',b'P5']
    poison = uuid4(); insert_event(owner,tenant,poison,payload={'event_id':str(poison),'secret':'never-copy-error-text'})
    failed = OutboxPublisher(app,Producer(fail=True),max_attempts=2)
    assert failed.deliver_once(tenant).retried == 1
    with psycopg.connect(owner) as conn:
        conn.execute("UPDATE platform.outbox SET available_at=now()-interval '1 second' WHERE id=%s",(poison,))
    assert failed.deliver_once(tenant).dead_lettered == 1
    with psycopg.connect(owner) as conn:
        dlq = conn.execute("SELECT id,error_code FROM platform.event_dlq WHERE source_event_id=%s",(poison,)).fetchone()
        assert dlq[1] == 'TimeoutError'
    assert failed.replay(tenant,dlq[0])
    assert not failed.replay(tenant,dlq[0])


def test_job_priority_lease_retry_and_poison_isolation(event_db):
    owner,app,tenant = event_db
    workspace,environment = uuid4(),uuid4()
    with psycopg.connect(owner) as conn:
        conn.execute("INSERT INTO platform.workspaces VALUES(%s,%s,'jobs',1)",(tenant,workspace))
        conn.execute("INSERT INTO platform.environments(tenant_id,id,workspace_id,name,kind,version) VALUES(%s,%s,%s,'test','test',1)",(tenant,environment,workspace))
        for priority in ('P5','P2'):
            conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,max_attempts,idempotency_key) VALUES(%s,%s,%s,%s,'report',%s,'{}',2,%s)",
                         (tenant,uuid4(),workspace,environment,priority,str(uuid4())))
    repo = JobRepository(app,max_batch=10)
    jobs = repo.claim(tenant)
    assert [job['priority'] for job in jobs] == ['P2','P5']
    repo.complete(tenant,jobs[0]['id'])
    repo.fail(tenant,jobs[1]['id'],RuntimeError('customer data omitted'))
    with psycopg.connect(owner) as conn:
        states = conn.execute("SELECT status,last_error_code FROM platform.jobs WHERE tenant_id=%s ORDER BY priority",(tenant,)).fetchall()
        assert ('completed',None) in states and ('retry','RuntimeError') in states
    job_id = uuid4()
    envelope = {'schema_version':'1.0.0','job_id':str(job_id),'tenant_id':str(tenant),
        'workspace_id':str(workspace),'environment_id':str(environment),'job_type':'report',
        'priority':'P4','attempt':0,'max_attempts':2,'not_before':None,
        'created_at':datetime.now(timezone.utc).isoformat(),'correlation_id':None,'payload':{'report':'x'}}
    assert repo.enqueue(envelope,idempotency_key='report-job-0000001')['id'] == job_id
    assert repo.enqueue(envelope,idempotency_key='report-job-0000001')['id'] == job_id
    with pytest.raises(ValueError): repo.enqueue({**envelope,'priority':'P0'},idempotency_key='bad-job-00000001')


def test_bounded_helpers_and_audit_verifier():
    assert cache_key('tenant','policy','active','1') == 'ag:tenant:policy:active:1'
    with pytest.raises(ValueError): cache_key('../tenant','policy','active','1')
    limits = QueueLimits(10,100)
    assert admitted(tenant_depth=10,global_depth=100,priority='P2',limits=limits)
    assert not admitted(tenant_depth=10,global_depth=100,priority='P5',limits=limits)
    result = percentiles([100,200,300,400,500])
    assert runtime_slo_passes(result)
    assert verify_links([{'id':1,'prev_hash':None,'record_hash':'sha256:'+'a'*64},
                         {'id':2,'prev_hash':'sha256:'+'a'*64,'record_hash':'sha256:'+'b'*64}])[0]
