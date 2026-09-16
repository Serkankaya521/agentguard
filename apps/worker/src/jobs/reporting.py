"""Bounded, tenant-scoped asynchronous report generation."""
import csv
from datetime import date, datetime
import hashlib
import io
import json

import psycopg
from psycopg.rows import dict_row


MEDIA = {'json':'application/json','csv':'text/csv','pdf':'application/pdf'}


def _json_value(value):
    if isinstance(value,(datetime,date)):
        return value.isoformat()
    return str(value)


def _minimal_pdf(lines: list[str]) -> bytes:
    text = '\\n'.join(lines)[:100_000]
    escaped = text.replace('\\','\\\\').replace('(','\\(').replace(')','\\)').replace('\n',') Tj 0 -14 Td (')
    stream = f"BT /F1 9 Tf 40 800 Td ({escaped}) Tj ET".encode('latin-1','replace')
    objects = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
        b'<< /Length '+str(len(stream)).encode()+b' >>\nstream\n'+stream+b'\nendstream',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ]
    result = bytearray(b'%PDF-1.4\n')
    offsets=[0]
    for index,obj in enumerate(objects,1):
        offsets.append(len(result)); result.extend(f'{index} 0 obj\n'.encode()+obj+b'\nendobj\n')
    xref=len(result); result.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]: result.extend(f'{offset:010d} 00000 n \n'.encode())
    result.extend(f'trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(result)


def _serialize(rows: list[dict], output_format: str) -> bytes:
    if output_format == 'json':
        return (json.dumps(rows,default=_json_value,separators=(',',':'),sort_keys=True)+'\n').encode()
    columns = sorted({key for row in rows for key in row})
    if output_format == 'csv':
        target=io.StringIO(newline=''); writer=csv.DictWriter(target,fieldnames=columns)
        writer.writeheader(); writer.writerows([{k:_json_value(v) for k,v in row.items()} for row in rows])
        return target.getvalue().encode()
    if output_format == 'pdf':
        return _minimal_pdf([','.join(columns),*[' | '.join(_json_value(row.get(k,'')) for k in columns) for row in rows]])
    raise ValueError('UNSUPPORTED_REPORT_FORMAT')


class ReportGenerator:
    def __init__(self, dsn: str, object_store, *, max_rows: int = 10_000):
        if not 1 <= max_rows <= 100_000:
            raise ValueError('invalid report row bound')
        self.dsn,self.object_store,self.max_rows=dsn,object_store,max_rows

    def __call__(self, envelope: dict):
        tenant_id, report_id = envelope['tenant_id'],envelope['payload']['report_id']
        with psycopg.connect(self.dsn,row_factory=dict_row,
                             options='-c statement_timeout=10000 -c lock_timeout=1000') as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant_id,))
            report=conn.execute('SELECT * FROM platform.reports WHERE id=%s FOR UPDATE',(report_id,)).fetchone()
            if not report:
                raise ValueError('REPORT_NOT_FOUND')
            if report['status']=='completed':
                return {'status':'completed','object_key':report['object_key']}
            conn.execute("UPDATE platform.reports SET status='running',error_code=NULL WHERE id=%s",(report_id,))
            try:
                rows=self._rows(conn,report)
                content=_serialize(rows,report['output_format'])
                digest=hashlib.sha256(content).hexdigest()
                key=f"{tenant_id}/reports/{report_id}.{report['output_format']}"
                metadata=self.object_store.put(tenant_id,key,content,sha256=digest,media_type=MEDIA[report['output_format']])
                if metadata.sha256 != digest or metadata.size_bytes != len(content):
                    raise ValueError('OBJECT_INTEGRITY_MISMATCH')
                conn.execute("UPDATE platform.reports SET status='completed',object_key=%s,object_hash=%s,size_bytes=%s,completed_at=clock_timestamp() WHERE id=%s",
                             (key,digest,len(content),report_id))
                return {'status':'completed','object_key':key,'sha256':digest}
            except Exception as exc:
                code=type(exc).__name__.upper()[:64]
                conn.execute("UPDATE platform.reports SET status='failed',error_code=%s WHERE id=%s",(code,report_id))
                raise

    def _rows(self,conn,report):
        common=(report['workspace_id'],report['period_start'],report['period_end'],self.max_rows)
        if report['report_type']=='findings':
            return conn.execute('SELECT id,environment_id,state,document,created_at FROM platform.findings WHERE workspace_id=%s AND created_at>=%s AND created_at<%s ORDER BY created_at,id LIMIT %s',common).fetchall()
        if report['report_type']=='audit':
            return conn.execute('SELECT id,identity_id,action,resource_id,created_at,record_hash FROM platform.audit WHERE created_at>=%s AND created_at<%s ORDER BY id LIMIT %s',
                                (report['period_start'],report['period_end'],self.max_rows)).fetchall()
        if report['report_type']=='runtime_summary':
            return [{'message':'runtime analytics are supplied by the ClickHouse export stage',
                     'period_start':report['period_start'],'period_end':report['period_end']}]
        raise ValueError('UNSUPPORTED_REPORT_TYPE')
