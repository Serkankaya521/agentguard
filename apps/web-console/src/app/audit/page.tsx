'use client';
import {useCallback, useEffect, useState} from 'react';
import {Badge, ErrorNote, PageHead} from '@/components/ui';
import {AuditRecord, control, explain} from '@/lib/control';
import {auditLabel, shortId, when} from '@/lib/format';
import {useT} from '@/lib/i18n';

const PAGE = 50;

export default function AuditPage() {
  const {t} = useT();
  const [rows, setRows] = useState<AuditRecord[]>([]);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [done, setDone] = useState(false);

  // The audit trail is a tamper-evident hash chain: each record's hash covers the
  // previous one, so verify() recomputing the chain is the integrity proof.
  const verify = useCallback(() => {
    setVerified(null);
    control<{valid: boolean}>('v1/audit/verify').then(r => setVerified(r.valid)).catch(() => setVerified(null));
  }, []);

  useEffect(() => {
    verify();
    control<AuditRecord[]>(`v1/audit?limit=${PAGE}`)
      .then(r => { setRows(r); setDone(r.length < PAGE); })
      .catch(e => setError(explain(e))).finally(() => setLoading(false));
  }, [verify]);

  async function loadMore() {
    if (!rows.length) return;
    setMore(true); setError('');
    try {
      const after = rows[rows.length - 1].id;
      const next = await control<AuditRecord[]>(`v1/audit?after=${after}&limit=${PAGE}`);
      setRows(prev => [...prev, ...next]);
      if (next.length < PAGE) setDone(true);
    } catch (e) { setError(explain(e)); } finally { setMore(false); }
  }

  const badge = verified === null
    ? <Badge>{t('audit.verifying')}</Badge>
    : verified
      ? <Badge tone="verified">{t('audit.verified')}</Badge>
      : <Badge tone="breach">{t('audit.verifyFailed')}</Badge>;

  return <>
    <PageHead title={t('audit.title')} description={t('audit.desc')}
      actions={<button onClick={verify}>{t('audit.reverify')}</button>}/>
    <ErrorNote message={error}/>

    <div className={`verdict ${verified === false ? 'breach' : 'verified'}`} style={{marginBottom: 20}}>
      <span className="verdict-dot" aria-hidden="true"/>
      <div><strong>{badge}</strong><p>{t('audit.chainNote')}</p></div>
    </div>

    {loading ? <p className="muted">{t('common.loading')}</p>
      : rows.length === 0 ? <div className="panel"><p className="muted" style={{margin: 0}}>{t('audit.noRecords')}</p></div>
      : <><div className="table-wrap"><table>
          <thead><tr><th>{t('col.time')}</th><th>{t('col.action')}</th><th>{t('col.identity')}</th>
            <th>{t('col.resource')}</th><th>{t('col.recordHash')}</th></tr></thead>
          <tbody>{rows.map(row => <tr key={row.id}>
            <td>{when(row.occurred_at)}</td>
            <td>{auditLabel(row.action, t)}<div className="hash">{row.action}</div></td>
            <td className="hash">{shortId(row.identity_id)}</td>
            <td className="hash">{shortId(row.resource_id)}</td>
            <td className="hash" title={row.record_hash || ''}>{row.record_hash ? row.record_hash.slice(0, 23) + '…' : '—'}</td>
          </tr>)}</tbody></table></div>
        {!done && <div style={{marginTop: 14}}>
          <button onClick={loadMore} disabled={more}>{more ? t('common.loading') : t('audit.loadMore')}</button></div>}
      </>}
  </>;
}
