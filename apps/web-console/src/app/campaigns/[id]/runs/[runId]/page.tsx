'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {EvolutionGrid} from '@/components/evolution-grid';
import {Badge, ErrorNote, Figures, PageHead} from '@/components/ui';
import {control, controlUrl, explain, Finding, idempotencyKey, RunView} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {duration, findingTone, origin, regressionTone, runTone, score, shortId, VERDICT_TONE, when} from '@/lib/format';

function FindingBlock({finding, onReplay, busy}: {finding: Finding; onReplay: (caseId: string) => void; busy: boolean}) {
  const {t} = useT();
  const doc = finding.document;
  const regression = finding.regression;
  return <article className="finding">
    <h3>{doc.title || t('col.finding')} <Badge tone={findingTone(finding.state)}>{finding.state.toLowerCase().replace('_', ' ')}</Badge>
      {doc.severity && <Badge tone="breach">{doc.severity.toLowerCase()}</Badge>}</h3>
    <dl className="facts">
      <dt>{t('finding.rootCause')}</dt><dd>{doc.root_cause || '—'}</dd>
      <dt>{t('finding.winningMutations')}</dt><dd>{doc.successful_mutations?.join(' → ') || '—'}</dd>
      <dt>{t('evo.evidence')}</dt><dd className="hash">{doc.evidence_pattern || '—'}</dd>
      <dt>{t('finding.recommendedFix').replace('.', '')}</dt><dd>{doc.remediation || '—'}</dd>
      <dt>{t('finding.regression')}</dt><dd>{regression
        ? <><Badge tone={regressionTone(regression.status)}>{regression.status}</Badge>{' '}
            <span className="muted">{regression.last_run_at ? `${t('finding.lastReplayed')} ${when(regression.last_run_at)}` : t('finding.lastReplayed') + ': ' + t('common.never')}</span>{' '}
            <button disabled={busy} onClick={() => onReplay(regression.case_id)}>{t('finding.replay')}</button></>
        : t('common.none')}</dd>
    </dl>
  </article>;
}

export default function RunDetail() {
  const {t} = useT();
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

  if (!view) return error ? <ErrorNote message={error}/> : <p className="muted">{t('common.loading')}</p>;
  const {campaign, run, summary} = view;
  const report = (lang: string) => controlUrl(`v1/campaigns/${id}/runs/${runId}/report.pdf?lang=${lang}`);

  return <>
    <PageHead title={`${t('col.run')} ${shortId(run.id)}`}
      crumbs={<><Link href="/campaigns">{t('nav.campaigns')}</Link> / <Link href={`/campaigns/${id}`}>{campaign.name}</Link></>}
      description={<>{origin(campaign.target_config.api_base)} · {campaign.target_config.model}
        {view.environment && <> · {view.environment.name}</>} · <Badge tone={runTone(run.status)}>{run.status}</Badge></>}
      actions={<>
        <a className="button primary" href={report('tr')} download>{t('run.downloadTr')}</a>
        <a className="button" href={report('en')} download>{t('run.english')}</a>
      </>}/>
    <ErrorNote message={error}/>
    {notice && <p className="notice" role="status">{notice}</p>}
    {run.error_code && <p className="notice error">{t('run.partial', {code: run.error_code})}</p>}

    <div className={`verdict ${VERDICT_TONE[summary.verdict]}`}>
      <span className="verdict-dot" aria-hidden="true"/>
      <div><strong>{t(`verdict.${summary.verdict}.t`)}</strong><p>{t(`verdict.${summary.verdict}.d`)}</p></div>
    </div>

    <Figures items={[
      {label: t('col.requests'), value: summary.requests},
      {label: t('evo.generation') + 's', value: summary.generation_count},
      {label: t('run.findings'), value: summary.verified_findings, tone: summary.open_findings ? 'breach' : summary.verified_findings ? 'verified' : ''},
      {label: t('col.bestScore'), value: score(summary.best_score)},
      {label: t('col.took'), value: duration(run.started_at, run.completed_at)},
    ]}/>

    <section className="panel section">
      <h2>{t('run.evolved')}</h2>
      <p className="muted" style={{marginTop: -6}}>{t('run.evolvedNote')}</p>
      <EvolutionGrid candidates={view.candidates}/>
      {view.candidates_truncated && <p className="muted">{t('run.showingFirst', {n: view.candidates.length})}</p>}
    </section>

    <div className="split section">
      <section className="panel">
        <h2>{t('run.findings')}</h2>
        {view.findings.length === 0
          ? <p className="muted" style={{margin: 0}}>{t('run.noFindings')}</p>
          : view.findings.map(finding => <FindingBlock key={finding.id} finding={finding} onReplay={replay} busy={busy}/>)}
      </section>
      <section className="panel">
        <h2>{t('run.sealedEvidence')}</h2>
        {view.evidence ? <dl className="facts">
          <dt>{t('evidence.object')}</dt><dd className="hash">{view.evidence.object_key}</dd>
          <dt>SHA-256</dt><dd className="hash">{view.evidence.object_hash}</dd>
          <dt>{t('evidence.size')}</dt><dd>{view.evidence.size_bytes.toLocaleString()} B</dd>
          <dt>{t('evidence.sealed')}</dt><dd>{when(view.evidence.created_at)}</dd>
        </dl> : <p className="muted" style={{margin: 0}}>{t('run.evidencePending')}</p>}
        <p className="muted" style={{marginBottom: 0}}>{t('run.evidenceNote')}</p>
      </section>
    </div>
  </>;
}
