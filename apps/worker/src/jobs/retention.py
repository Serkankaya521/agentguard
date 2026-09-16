"""Report artifact retention; audit chain records are deliberately never deleted."""
import psycopg
from psycopg.rows import dict_row


class ReportRetention:
    def __init__(self, dsn: str, object_store, *, batch_size: int = 100):
        if not 1 <= batch_size <= 1000:
            raise ValueError('invalid retention batch')
        self.dsn,self.object_store,self.batch_size=dsn,object_store,batch_size

    def run_tenant(self,tenant_id: str) -> int:
        with psycopg.connect(self.dsn,row_factory=dict_row,
                             options='-c statement_timeout=10000 -c lock_timeout=1000') as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant_id,))
            rows=conn.execute(
                "SELECT id,object_key FROM platform.reports WHERE expires_at<=now() AND status IN ('completed','failed') "
                "ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT %s",(self.batch_size,),).fetchall()
            for row in rows:
                if row['object_key']:
                    self.object_store.delete(tenant_id,row['object_key'])
                conn.execute("UPDATE platform.reports SET status='expired',object_key=NULL WHERE id=%s",(row['id'],))
            return len(rows)
