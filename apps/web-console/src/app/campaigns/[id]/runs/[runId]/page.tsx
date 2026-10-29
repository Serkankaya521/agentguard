'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {EvolutionGrid} from '@/components/evolution-grid';
import {Badge, ErrorNote, Figures, PageHead} from '@/components/ui';
import {control, controlUrl, explain, Finding, idempotencyKey, RunView} from '@/lib/control';
import {duration, findingTone, origin, regressionTone, runTone, score, shortId, VERDICT, when} from '@/lib/format';

function FindingBlock({finding, onReplay, busy}: {finding: Finding; onReplay: (caseId: string) => void; busy: boolean}) {
  const doc = finding.document;
  const regression = finding.regression;
  return <article className="finding">
    <h3>{doc.title || 'Finding'} <Badge tone={findingTone(finding.state)}>{finding.state.toLowerCase().replace('_', ' ')}</Badge>
      {doc.severity && <Badge tone="breach">{doc.severity.toLowerCase()}</Badge>}</h3>
    <dl className="facts">
      <dt>What happened</dt><dd>{doc.root_cause || '—'}</dd>
      <dt>Winning mutations</dt><dd>{doc.successful_mutations?.join(' → ') || '—'}</dd>
      <dt>Evidence</dt><dd className="hash">{doc.evidence_pattern || '—'}</dd>
      <dt>Fix</dt><dd>{doc.remediation || '—'}</dd>
      <dt>Regression</dt><dd>{regression
        ? <><Badge tone={regressionTone(regression.status)}>{regression.status}</Badge>{' '}
            <span className="muted">{regression.last_run_at ? `last replayed ${when(regression.last_run_at)}` : 'not replayed yet'}</span>{' '}
            <button disabled={busy} onClick={() => onReplay(regression.case_id)}>Replay exploit</button></>
        : 'no regression case'}</dd>
    </dl>
  </article>;
}

export default function RunDetail() {
  const {id, runId} = useParams<{id: string; runId: string}>();
  const [view, setView] = useState<RunView>();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    control<RunView>(`v1/campaigns/${id}/runs/${runId}`).then(setView).catch(e => setError(explain(e)));
  }, [id, runId]);
  useEffect(load, [load]);
  const live = view && (view.run.status === 'queued' || view.run.status === 'running');
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(load, 4000);
    return () => clearInterval(timer);
  }, [live, load]);

  async function replay(caseId: string) {
    setBusy(true); setError(''); setNotice('');
    try {
      await control(`v1/regression-cases/${caseId}/runs`, {method: 'POST', headers: {'Idempotency-Key': idempotencyKey(`replay-${caseId}`)}});
      setNotice('Replay queued. The regression status updates when the worker finishes.');
    } catch (e) { setError(explain(e)); } finally { setBusy(false); }
  }

  if (!view) return error ? <ErrorNote message={error}/> : <p className="muted">Loading…</p>;
  const {campaign, run, summary} = view;
  const verdict = VERDICT[summary.verdict];
  const report = (lang: string) => controlUrl(`v1/campaigns/${id}/runs/${runId}/report.pdf?lang=${lang}`);

  return <>
    <PageHead title={`Run ${shortId(run.id)}`}
      crumbs={<><Link href="/campaigns">Campaigns</Link> / <Link href={`/campaigns/${id}`}>{campaign.name}</Link></>}
      description={<>{origin(campaign.target_config.api_base)} · {campaign.target_config.model}
        {view.environment && <> · {view.environment.name}</>} · <Badge tone={runTone(run.status)}>{run.status}</Badge></>}
      actions={<>
        <a className="button primary" href={report('tr')} download>Download report (TR)</a>
        <a className="button" href={report('en')} download>English</a>
      </>}/>
    <ErrorNote message={error}/>
    {notice && <p className="notice" role="status">{notice}</p>}
    {run.error_code && <p className="notice error">The run stopped with {run.error_code}. Results below are partial.</p>}

    <div className={`verdict ${verdict.tone}`}>
      <span className="verdict-dot" aria-hidden="true"/>
      <div><strong>{verdict.title}</strong><p>{verdict.detail}</p></div>
    </div>

    <Figures items={[
      {label: 'Requests sent', value: summary.requests},
      {label: 'Generations', value: summary.generation_count},
      {label: 'Verified findings', value: summary.verified_findings, tone: summary.open_findings ? 'breach' : summary.verified_findings ? 'verified' : ''},
      {label: 'Best heuristic score', value: score(summary.best_score)},
      {label: 'Duration', value: duration(run.started_at, run.completed_at)},
    ]}/>

    <section className="panel section">
      <h2>How the attack evolved</h2>
      <p className="muted" style={{marginTop: -6}}>Each square is one attack the campaign sent. Darker means the response moved
        closer to the objective; red means the agent revealed the planted canary. Select a square to see the attack.</p>
      <EvolutionGrid candidates={view.candidates}/>
      {view.candidates_truncated && <p className="muted">Showing the first {view.candidates.length} candidates.</p>}
    </section>

    <div className="split section">
      <section className="panel">
        <h2>Verified findings</h2>
        {view.findings.length === 0
          ? <p className="muted" style={{margin: 0}}>No finding in this run. Findings are created only from target-side evidence.</p>
          : view.findings.map(finding => <FindingBlock key={finding.id} finding={finding} onReplay={replay} busy={busy}/>)}
      </section>
      <section className="panel">
        <h2>Sealed evidence</h2>
        {view.evidence ? <dl className="facts">
          <dt>Object</dt><dd className="hash">{view.evidence.object_key}</dd>
          <dt>SHA-256</dt><dd className="hash">{view.evidence.object_hash}</dd>
          <dt>Size</dt><dd>{view.evidence.size_bytes.toLocaleString()} bytes</dd>
          <dt>Sealed</dt><dd>{when(view.evidence.created_at)}</dd>
        </dl> : <p className="muted" style={{margin: 0}}>Evidence is sealed when the run completes.</p>}
        <p className="muted" style={{marginBottom: 0}}>Raw agent responses are never stored. Only their digests are kept, so the
          evidence can be verified without holding leaked data.</p>
      </section>
    </div>
  </>;
}
