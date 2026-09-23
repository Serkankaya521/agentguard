"""Bounded per-tenant scheduled report materializer."""
from datetime import datetime,timedelta,timezone
import os
from uuid import uuid4,uuid5
import psycopg
from psycopg.rows import dict_row
from tenant_ids import active_tenant_ids

def run_tenant(dsn,tenant_id,batch_size=50):
    with psycopg.connect(dsn,row_factory=dict_row) as conn:
        conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant_id,))
        rows=conn.execute("SELECT * FROM platform.report_schedules WHERE enabled AND next_run_at<=now() ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT %s",(batch_size,)).fetchall()
        now=datetime.now(timezone.utc)
        for schedule in rows:
            report_id=uuid4();start=now-timedelta(minutes=schedule['lookback_minutes'])
            limits=conn.execute('INSERT INTO platform.tenant_operating_limits(tenant_id) VALUES(%s) ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=excluded.tenant_id RETURNING report_retention_days',(tenant_id,)).fetchone()
            conn.execute('INSERT INTO platform.reports(tenant_id,id,workspace_id,environment_id,requested_by,report_type,output_format,period_start,period_end,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(tenant_id,report_id,schedule['workspace_id'],schedule['environment_id'],schedule['created_by'],schedule['report_type'],schedule['output_format'],start,now,now+timedelta(days=limits['report_retention_days'])))
            payload={'report_id':str(report_id),'report_type':schedule['report_type'],'output_format':schedule['output_format'],'period_start':start.isoformat(),'period_end':now.isoformat()}
            conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,idempotency_key,max_attempts) VALUES(%s,%s,%s,%s,'report.generate','P4',%s,%s,5)",(tenant_id,report_id,schedule['workspace_id'],schedule['environment_id'],psycopg.types.json.Jsonb(payload),f"schedule:{schedule['id']}:{schedule['next_run_at'].isoformat()}"))
            conn.execute('UPDATE platform.report_schedules SET next_run_at=next_run_at+(interval_minutes*interval \'1 minute\') WHERE id=%s',(schedule['id'],))
        campaign_rows=conn.execute("SELECT * FROM platform.campaigns WHERE status='active' AND next_run_at<=now() ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT %s",(batch_size,)).fetchall()
        for campaign in campaign_rows:
            scheduled_for=campaign['next_run_at']
            # Derive both identifiers from the campaign and schedule slot so a
            # transaction retry produces the same run/job pair.
            run_id=uuid5(campaign['id'],scheduled_for.isoformat())
            job_id=uuid5(run_id,'red_team.execute')
            conn.execute('INSERT INTO platform.campaign_runs(tenant_id,id,campaign_id,scheduled_for) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',(tenant_id,run_id,campaign['id'],scheduled_for))
            payload={'campaign_id':str(campaign['id']),'run_id':str(run_id)}
            conn.execute("INSERT INTO platform.jobs(tenant_id,id,workspace_id,environment_id,job_type,priority,payload,idempotency_key,max_attempts) VALUES(%s,%s,%s,%s,'red_team.execute','P3',%s,%s,5) ON CONFLICT(tenant_id,idempotency_key) DO NOTHING",(tenant_id,job_id,campaign['workspace_id'],campaign['environment_id'],psycopg.types.json.Jsonb(payload),f"campaign:{campaign['id']}:{scheduled_for.isoformat()}"))
            conn.execute("UPDATE platform.campaigns SET next_run_at=next_run_at+(interval_minutes*interval '1 minute'),updated_at=clock_timestamp() WHERE id=%s",(campaign['id'],))
        return len(rows)+len(campaign_rows)

def main():
    tenants=active_tenant_ids(os.environ['CONTROL_DATABASE_URL'])
    for tenant in tenants:run_tenant(os.environ['CONTROL_DATABASE_URL'],tenant)
if __name__=='__main__':main()
