'use client';
import Link from 'next/link';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead} from '@/components/ui';
import {control, explain, idempotencyKey} from '@/lib/control';
import {regressionTone, shortId, when} from '@/lib/format';

type RegressionCase = {id: string; finding_id: string; campaign_id: string; expected_block: boolean;
                       status: string; last_run_at: string | null; created_at: string};

export default function RegressionCases() {
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
    <PageHead title="Regression cases"
      description="Every confirmed leak is kept as a replayable exploit. Replay after a fix: passed means the agent no longer leaks, reopened means the weakness is back."
      actions={<button onClick={load}>Refresh</button>}/>
    <ErrorNote message={error}/>
    {cases && (cases.length === 0
      ? <div className="panel"><Empty title="No regression cases yet">They are created automatically from confirmed findings.</Empty></div>
      : <div className="table-wrap"><table>
          <thead><tr><th>Case</th><th>Campaign</th><th>Status</th><th>Last replay</th><th>Created</th><th/></tr></thead>
          <tbody>{cases.map(row => <tr key={row.id}>
            <td><code>{shortId(row.id)}</code><div className="hash">finding {shortId(row.finding_id)}</div></td>
            <td><Link href={`/campaigns/${row.campaign_id}`}>{shortId(row.campaign_id)}</Link></td>
            <td><Badge tone={regressionTone(row.status)}>{row.status}</Badge></td>
            <td>{row.last_run_at ? when(row.last_run_at) : 'never'}</td>
            <td>{when(row.created_at)}</td>
            <td>{queued.has(row.id) ? <span className="muted">Replay queued</span>
              : <button onClick={() => replay(row.id)}>Replay exploit</button>}</td>
          </tr>)}</tbody></table></div>)}
  </>;
}
