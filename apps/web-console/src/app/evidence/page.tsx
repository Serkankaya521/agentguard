'use client';
import Link from 'next/link';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead} from '@/components/ui';
import {control, explain, idempotencyKey} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {regressionTone, shortId, when} from '@/lib/format';

type RegressionCase = {id: string; finding_id: string; campaign_id: string; expected_block: boolean;
                       status: string; last_run_at: string | null; created_at: string};

export default function RegressionCases() {
  const {t} = useT();
  const [cases, setCases] = useState<RegressionCase[]>();
  const [error, setError] = useState('');
  const [queued, setQueued] = useState<Set<string>>(new Set());

  const load = useCallback(() => {
    control<RegressionCase[]>('v1/regression-cases').then(setCases).catch(e => setError(explain(e)));
  }, []);
  useEffect(load, [load]);

  async function replay(id: string) {
    setError('');
    try {
      await control(`v1/regression-cases/${id}/runs`, {method: 'POST', headers: {'Idempotency-Key': idempotencyKey(`replay-${id}`)}});
      setQueued(previous => new Set(previous).add(id));
    } catch (e) { setError(explain(e)); }
  }

  return <>
    <PageHead title={t('regr.title')} description={t('regr.desc')}
      actions={<button onClick={load}>{t('common.refresh')}</button>}/>
    <ErrorNote message={error}/>
    {cases && (cases.length === 0
      ? <div className="panel"><Empty title={t('regr.none')}>{t('regr.noneBody')}</Empty></div>
      : <div className="table-wrap"><table>
          <thead><tr><th>{t('col.case')}</th><th>{t('col.campaignCol')}</th><th>{t('common.status')}</th><th>{t('col.lastReplay')}</th><th>{t('col.created')}</th><th/></tr></thead>
          <tbody>{cases.map(row => <tr key={row.id}>
            <td><code>{shortId(row.id)}</code><div className="hash">{t('col.finding').toLowerCase()} {shortId(row.finding_id)}</div></td>
            <td><Link href={`/campaigns/${row.campaign_id}`}>{shortId(row.campaign_id)}</Link></td>
            <td><Badge tone={regressionTone(row.status)}>{row.status}</Badge></td>
            <td>{row.last_run_at ? when(row.last_run_at) : t('common.never')}</td>
            <td>{when(row.created_at)}</td>
            <td>{queued.has(row.id) ? <span className="muted">{t('regr.replayQueued')}</span>
              : <button onClick={() => replay(row.id)}>{t('regr.replay')}</button>}</td>
          </tr>)}</tbody></table></div>)}
  </>;
}
