"""Durable, tenant-scoped, lease-based job repository."""
from datetime import timedelta
from uuid import uuid4
import psycopg
from psycopg.rows import dict_row
from validation import validate
from queues.backpressure import QueueLimits, admitted


class JobRepository:
    def __init__(self, dsn: str, *, max_batch: int = 32):
        if not 1 <= max_batch <= 100:
            raise ValueError("unbounded batch")
        self.dsn, self.max_batch = dsn, max_batch

    def enqueue(self, envelope: dict, *, idempotency_key: str,
                global_depth: int = 0, limits: QueueLimits = QueueLimits()):
        errors = validate(envelope,"job_envelope")
        if errors:
            raise ValueError("job schema invalid")
        tenant_id = envelope['tenant_id']
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant_id,))
            depth = conn.execute("SELECT count(*) AS n FROM platform.jobs WHERE status IN ('queued','retry','running')").fetchone()['n']
            if not admitted(tenant_depth=depth,global_depth=global_depth,
                            priority=envelope['priority'],limits=limits):
                raise RuntimeError('QUEUE_CAPACITY_EXCEEDED')
            existing = conn.execute("SELECT * FROM platform.jobs WHERE idempotency_key=%s",(idempotency_key,)).fetchone()
            if existing:
                return existing
            return conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,attempt,max_attempts,not_before,idempotency_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,coalesce(%s::timestamptz,now()),%s) RETURNING *",
                (tenant_id,envelope['job_id'],envelope.get('workspace_id'),envelope.get('environment_id'),
                 envelope['job_type'],envelope['priority'],psycopg.types.json.Jsonb(envelope['payload']),
                 envelope['attempt'],envelope['max_attempts'],envelope.get('not_before'),idempotency_key)).fetchone()

    def claim(self, tenant_id, *, lease_seconds: int = 30, job_types=None):
        if not 5 <= lease_seconds <= 300:
            raise ValueError("invalid lease")
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (str(tenant_id),))
            # Reclaim work abandoned by a crashed worker. Attempts were already
            # incremented at the original claim, so the normal max-attempt path
            # remains authoritative when the job fails again.
            conn.execute(
                "UPDATE platform.jobs SET status=CASE WHEN attempt>=max_attempts THEN 'dead_letter' ELSE 'retry' END,"
                "last_error_code='LEASE_EXPIRED',lease_until=NULL,not_before=now() "
                "WHERE status='running' AND lease_until<now()")
            allowed=tuple(job_types or ())
            type_filter=" AND job_type=ANY(%s)" if allowed else ""
            params=(list(allowed),self.max_batch) if allowed else (self.max_batch,)
            rows = conn.execute(
                "SELECT * FROM platform.jobs WHERE status IN ('queued','retry') AND not_before<=now() "
                "AND (lease_until IS NULL OR lease_until<now()) "+type_filter+
                " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,created_at "
                "FOR UPDATE SKIP LOCKED LIMIT %s",params).fetchall()
            for row in rows:
                conn.execute("UPDATE platform.jobs SET status='running',attempt=attempt+1,lease_until=now()+(%s*interval '1 second') WHERE tenant_id=%s AND id=%s",
                             (lease_seconds,row['tenant_id'],row['id']))
                row['attempt'] += 1
            valid = []
            for row in rows:
                envelope = {"schema_version":"1.0.0","job_id":str(row['id']),
                    "tenant_id":str(row['tenant_id']),"workspace_id":str(row['workspace_id']) if row['workspace_id'] else None,
                    "environment_id":str(row['environment_id']) if row['environment_id'] else None,
                    "job_type":row['job_type'],"priority":row['priority'],"attempt":row['attempt'],
                    "max_attempts":row['max_attempts'],"not_before":row['not_before'].isoformat(),
                    "created_at":row['created_at'].isoformat(),"correlation_id":None,"payload":row['payload']}
                if validate(envelope,"job_envelope"):
                    conn.execute("UPDATE platform.jobs SET status='dead_letter',last_error_code='SCHEMA_INVALID',lease_until=NULL WHERE tenant_id=%s AND id=%s",
                                 (row['tenant_id'],row['id']))
                else:
                    row['envelope'] = envelope
                    valid.append(row)
            return valid

    def complete(self, tenant_id, job_id):
        with psycopg.connect(self.dsn) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (str(tenant_id),))
            conn.execute("UPDATE platform.jobs SET status='completed',lease_until=NULL WHERE tenant_id=%s AND id=%s AND status='running'",(tenant_id,job_id))

    def fail(self, tenant_id, job_id, exc):
        from queues.dlq import error_code
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (str(tenant_id),))
            row = conn.execute("SELECT attempt,max_attempts,job_type,payload FROM platform.jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",(tenant_id,job_id)).fetchone()
            if not row:
                return
            dead = row['attempt'] >= row['max_attempts']
            delay = min(300,2 ** row['attempt'])
            conn.execute("UPDATE platform.jobs SET status=%s,last_error_code=%s,lease_until=NULL,not_before=now()+(%s*interval '1 second') WHERE tenant_id=%s AND id=%s",
                         ('dead_letter' if dead else 'retry',error_code(exc),delay,tenant_id,job_id))
            if dead and row['job_type']=='red_team.execute' and row['payload'].get('run_id'):
                conn.execute("UPDATE platform.campaign_runs SET status='failed',completed_at=clock_timestamp(),error_code=%s WHERE id=%s AND status<>'completed'",(error_code(exc),row['payload']['run_id']))

    def replay_dead_letter(self, tenant_id, job_id):
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(str(tenant_id),))
            row = conn.execute("UPDATE platform.jobs SET status='queued',attempt=0,last_error_code=NULL,not_before=now() WHERE id=%s AND status='dead_letter' RETURNING *",(job_id,)).fetchone()
            return row is not None
