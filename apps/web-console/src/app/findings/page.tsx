'use client';
import Link from 'next/link';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Finding} from '@/lib/control';
import {NEXT} from '@/lib/findings';
import {useT} from '@/lib/i18n';
import {findingTone, shortId, sla, when} from '@/lib/format';

const SEVERITY_RANK: Record<string, number> = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3};
const label = (state: string) => state.toLowerCase().replaceAll('_', ' ');

function FindingTable({workspaceId}: {workspaceId: string}) {
  const {t} = useT();
  const [rows, setRows] = useState<Finding[]>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [showClosed, setShowClosed] = useState(false);

  const load = useCallback(() => {
    control<Finding[]>(`v1/findings?workspace_id=${encodeURIComponent(workspaceId)}&limit=100`)
      .then(setRows).catch(e => setError(explain(e)));
  }, [workspaceId]);
  useEffect(load, [load]);

  async function transition(finding: Finding, state: string) {
    setBusy(finding.id); setError('');
    try {
      await control(`v1/findings/${finding.id}/transitions`, {method: 'POST',
        headers: {'If-Match': String(finding.version)}, body: JSON.stringify({state})});
      load();
    } catch (e) { setError(explain(e)); } finally { setBusy(''); }
  }

  if (!rows) return error ? <ErrorNote message={error}/> : <p className="muted">{t('common.loading')}</p>;
  const closed = (f: Finding) => f.state === 'RESOLVED_VERIFIED' || f.state === 'FALSE_POSITIVE';
  const visible = rows.filter(f => showClosed || !closed(f)).sort((a, b) =>
    Number(closed(a)) - Number(closed(b)) ||
    (SEVERITY_RANK[a.document.severity || ''] ?? 9) - (SEVERITY_RANK[b.document.severity || ''] ?? 9) ||
    b.created_at.localeCompare(a.created_at));

  return <>
    <ErrorNote message={error}/>
    <label className="field check" style={{marginBottom: 12}}>
      <input type="checkbox" checked={showClosed} onChange={e => setShowClosed(e.target.checked)}/>
      {t('findings.showClosed', {n: rows.filter(closed).length})}
    </label>
    {visible.length === 0
      ? <div className="panel"><Empty title={rows.length ? t('findings.noOpen') : t('findings.noneYet')}>
          {rows.length ? t('findings.allClosed') : t('findings.appearWhen')}
        </Empty></div>
      : <div className="table-wrap"><table>
          <thead><tr><th>{t('col.finding')}</th><th>{t('col.severity')}</th><th>{t('col.state')}</th><th>{t('col.sla')}</th><th>{t('col.source')}</th><th>{t('col.nextStep')}</th></tr></thead>
          <tbody>{visible.map(f => {
            const status = sla(f.document.severity, f.state, f.created_at, f.updated_at, t);
            return <tr key={f.id}>
              <td><Link href={`/findings/${f.id}`}><strong>{f.document.title || t('col.finding')}</strong></Link>
                <div className="hash">{shortId(f.id)} · {when(f.created_at)}</div></td>
              <td>{f.document.severity ? <Badge tone={SEVERITY_RANK[f.document.severity] <= 1 ? 'breach' : 'signal'}>{f.document.severity.toLowerCase()}</Badge> : '—'}</td>
              <td><Badge tone={findingTone(f.state)}>{label(f.state)}</Badge></td>
              <td>{status.tone ? <Badge tone={status.tone}>{status.label}</Badge> : <span className="muted">{status.label}</span>}</td>
              <td>{f.document.campaign_id && f.document.run_id
                ? <Link href={`/campaigns/${f.document.campaign_id}/runs/${f.document.run_id}`}>{t('col.run')} {shortId(f.document.run_id)}</Link>
                : t('common.manual')}</td>
              <td><div className="actions">{(NEXT[f.state] || []).map(([state, key]) =>
                <button key={state} disabled={busy === f.id} className={state === 'FALSE_POSITIVE' ? 'danger' : ''}
                  onClick={() => transition(f, state)}>{t(key)}</button>)}
                {f.state === 'RETESTING' && <Link href={`/findings/${f.id}`} className="muted">{t('findings.replayToClose')}</Link>}
              </div></td>
            </tr>;
          })}</tbody></table></div>}
  </>;
}

function FindingsHead() {
  const {t} = useT();
  return <PageHead title={t('findings.title')} description={t('findings.desc')}/>;
}

export default function Findings() {
  return <>
    <FindingsHead/>
    <RequireWorkspace>{workspaceId => <FindingTable key={workspaceId} workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
