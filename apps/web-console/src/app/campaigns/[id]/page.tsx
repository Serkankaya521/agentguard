'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead} from '@/components/ui';
import {Campaign, control, explain, idempotencyKey, Run} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {duration, every, origin, runTone, score, shortId, when} from '@/lib/format';

export default function CampaignDetail() {
  const {t} = useT();
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

  if (!campaign) return error ? <ErrorNote message={error}/> : <p className="muted">{t('common.loading')}</p>;
  const scheduled = campaign.status === 'active';
  return <>
    <PageHead title={campaign.name} crumbs={<Link href="/campaigns">{t('nav.campaigns')}</Link>}
      description={<>Target <span className="hash">{origin(campaign.target_config.api_base)}</span>, model {campaign.target_config.model}</>}
      actions={<>
        {campaign.status !== 'archived' && (scheduled
          ? <button disabled={busy} onClick={() => setStatus('paused')}>{t('campaign.pause')}</button>
          : campaign.interval_minutes && <button disabled={busy} onClick={() => setStatus('active')}>{t('campaign.resume')}</button>)}
        <button className="primary" disabled={busy || campaign.status === 'archived'} onClick={runNow}>{t('campaign.runNow')}</button>
      </>}/>
    <ErrorNote message={error}/>
    <div className="split">
      <section>
        <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12}}>
          <h2 style={{marginBottom: 0}}>{t('campaign.runs')}</h2>
          {runs.length >= 2 && <Link className="button" href={`/campaigns/${id}/compare`}>{t('run.compare')}</Link>}
        </div>
        {runs.length === 0
          ? <div className="panel"><Empty title={t('campaign.noRuns')}>{t('campaign.noRunsBody')}</Empty></div>
          : <div className="table-wrap"><table>
              <thead><tr><th>{t('col.run')}</th><th>{t('common.status')}</th><th className="num">{t('col.requests')}</th><th className="num">{t('col.findings')}</th>
                <th className="num">{t('col.bestScore')}</th><th>{t('col.started')}</th><th>{t('col.took')}</th></tr></thead>
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
        <h2>{t('campaign.config')}</h2>
        <div className="panel"><dl className="facts">
          <dt>{t('col.schedule')}</dt><dd>{scheduled ? `${every(campaign.interval_minutes, t)}, ${t('campaign.nextRun')} ${when(campaign.next_run_at)}` : campaign.status}</dd>
          <dt>{t('campaign.budget')}</dt><dd>{campaign.request_budget} {t('col.requests').toLowerCase()}, {campaign.mutation_budget} {t('campaigns.mutationBudget').toLowerCase()}</dd>
          <dt>{t('campaign.apiKey')}</dt><dd>{campaign.secret_configured ? t('campaign.referenced') : t('common.none')}</dd>
          <dt>{t('col.canary')}</dt><dd>{campaign.canary_configured ? t('campaign.referenced') : <Badge tone="signal">{t('campaign.canaryMissing')}</Badge>}</dd>
          <dt>{t('campaign.objectives')}</dt><dd>{campaign.objective_markers.join(', ')}</dd>
        </dl></div>
        <div className="panel"><h2>{t('campaign.seedPrompt')}</h2>
          <pre className="hash" style={{whiteSpace: 'pre-wrap', margin: 0}}>{campaign.seed_prompt}</pre></div>
      </section>
    </div>
  </>;
}
