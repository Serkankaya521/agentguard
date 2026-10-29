'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead} from '@/components/ui';
import {Campaign, control, explain, idempotencyKey, Run} from '@/lib/control';
import {duration, every, origin, runTone, score, shortId, when} from '@/lib/format';

export default function CampaignDetail() {
  const {id} = useParams<{id: string}>();
  const [campaign, setCampaign] = useState<Campaign>();
  const [runs, setRuns] = useState<Run[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    Promise.all([control<Campaign>(`v1/campaigns/${id}`), control<Run[]>(`v1/campaigns/${id}/runs`)])
      .then(([c, r]) => { setCampaign(c); setRuns(r); }).catch(e => setError(explain(e)));
  }, [id]);
  useEffect(load, [load]);

  // Poll while a run is in flight so the operator sees it finish.
  const inFlight = runs.some(run => run.status === 'queued' || run.status === 'running');
  useEffect(() => {
    if (!inFlight) return;
    const timer = setInterval(load, 4000);
    return () => clearInterval(timer);
  }, [inFlight, load]);

  async function act(work: () => Promise<unknown>) {
    setBusy(true); setError('');
    try { await work(); load(); } catch (e) { setError(explain(e)); } finally { setBusy(false); }
  }
  const runNow = () => act(() => control(`v1/campaigns/${id}/runs`, {method: 'POST',
    headers: {'Idempotency-Key': idempotencyKey(`run-${id}`)}}));
  const setStatus = (status: string) => act(() => control(`v1/campaigns/${id}/status`, {method: 'POST',
    headers: {'If-Match': String(campaign?.version)}, body: JSON.stringify({status})}));

  if (!campaign) return error ? <ErrorNote message={error}/> : <p className="muted">Loading…</p>;
  const scheduled = campaign.status === 'active';
  return <>
    <PageHead title={campaign.name} crumbs={<Link href="/campaigns">Campaigns</Link>}
      description={<>Target <span className="hash">{origin(campaign.target_config.api_base)}</span>, model {campaign.target_config.model}</>}
      actions={<>
        {campaign.status !== 'archived' && (scheduled
          ? <button disabled={busy} onClick={() => setStatus('paused')}>Pause schedule</button>
          : campaign.interval_minutes && <button disabled={busy} onClick={() => setStatus('active')}>Resume schedule</button>)}
        <button className="primary" disabled={busy || campaign.status === 'archived'} onClick={runNow}>Run now</button>
      </>}/>
    <ErrorNote message={error}/>
    <div className="split">
      <section>
        <h2>Runs</h2>
        {runs.length === 0
          ? <div className="panel"><Empty title="No runs yet">Use Run now to start the first test.</Empty></div>
          : <div className="table-wrap"><table>
              <thead><tr><th>Run</th><th>Status</th><th className="num">Requests</th><th className="num">Findings</th>
                <th className="num">Best score</th><th>Started</th><th>Took</th></tr></thead>
              <tbody>{runs.map(run => <tr key={run.id}>
                <td><Link href={`/campaigns/${id}/runs/${run.id}`}><code>{shortId(run.id)}</code></Link></td>
                <td><Badge tone={runTone(run.status)}>{run.status}</Badge>
                  {run.error_code && <div className="hash">{run.error_code}</div>}</td>
                <td className="num">{run.candidates_evaluated}</td>
                <td className="num">{run.findings_created ? <Badge tone="breach">{run.findings_created}</Badge> : 0}</td>
                <td className="num">{score(run.best_score)}</td>
                <td>{when(run.started_at || run.created_at)}</td>
                <td>{duration(run.started_at, run.completed_at)}</td>
              </tr>)}</tbody></table></div>}
      </section>
      <section>
        <h2>Configuration</h2>
        <div className="panel"><dl className="facts">
          <dt>Schedule</dt><dd>{scheduled ? `${every(campaign.interval_minutes)}, next ${when(campaign.next_run_at)}` : campaign.status}</dd>
          <dt>Budget</dt><dd>{campaign.request_budget} requests, {campaign.mutation_budget} mutations</dd>
          <dt>API key</dt><dd>{campaign.secret_configured ? 'referenced' : 'none'}</dd>
          <dt>Canary</dt><dd>{campaign.canary_configured ? 'referenced' : <Badge tone="signal">missing — findings cannot be confirmed</Badge>}</dd>
          <dt>Objectives</dt><dd>{campaign.objective_markers.join(', ')}</dd>
        </dl></div>
        <div className="panel"><h2>Seed prompt</h2>
          <pre className="hash" style={{whiteSpace: 'pre-wrap', margin: 0}}>{campaign.seed_prompt}</pre></div>
      </section>
    </div>
  </>;
}
