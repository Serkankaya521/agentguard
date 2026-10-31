'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {Badge, ErrorNote, PageHead} from '@/components/ui';
import {control, explain, FindingDetail, idempotencyKey} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {auditLabel, categoryLabel, findingTone, owaspLabel, regressionTone, shortId, sla, when} from '@/lib/format';
import {NEXT} from '@/lib/findings';

const label = (state: string) => state.toLowerCase().replaceAll('_', ' ');

export default function FindingPage() {
  const {t, lang} = useT();
  const {id} = useParams<{id: string}>();
  const [data, setData] = useState<FindingDetail>();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    control<FindingDetail>(`v1/findings/${id}/detail?lang=${lang}`).then(setData).catch(e => setError(explain(e)));
  }, [id, lang]);
  useEffect(load, [load]);

  async function act(work: () => Promise<unknown>, done = '') {
    setBusy(true); setError(''); setNotice('');
    try { await work(); if (done) setNotice(done); load(); }
    catch (e) { setError(explain(e)); } finally { setBusy(false); }
  }
  const transition = (state: string) => act(() => control(`v1/findings/${id}/transitions`,
    {method: 'POST', headers: {'If-Match': String(data?.finding.version)}, body: JSON.stringify({state})}));
  const replay = (caseId: string) => act(() => control(`v1/regression-cases/${caseId}/runs`,
    {method: 'POST', headers: {'Idempotency-Key': idempotencyKey(`replay-${caseId}`)}}),
    t('run.replayQueued'));
  const sendFeedback = (verdict: 'good' | 'bad' | 'clear') => act(
    () => control(`v1/findings/${id}/feedback`, {method: 'POST', body: JSON.stringify({verdict})}),
    t('finding.fbSaved'));

  if (!data) return error ? <ErrorNote message={error}/> : <p className="muted">{t('common.loading')}</p>;
  const {finding, origin, regression, timeline, category, remediation_detail, attack_trace, feedback} = data;
  const doc = finding.document;
  const status = sla(doc.severity, finding.state, finding.created_at, finding.updated_at, t);
  const severe = (doc.severity || '').toUpperCase();

  return <>
    <PageHead title={doc.title || t('col.finding')} crumbs={<Link href="/findings">{t('findings.title')}</Link>}
      description={<>{shortId(finding.id)} · {t('finding.firstSeen')} {when(finding.created_at)}</>}
      actions={<div className="actions">{(NEXT[finding.state] || []).map(([state, key]) =>
        <button key={state} disabled={busy} className={state === 'FALSE_POSITIVE' ? 'danger' : state === 'CONFIRMED' ? 'primary' : ''}
          onClick={() => transition(state)}>{t(key)}</button>)}</div>}/>
    <ErrorNote message={error}/>
    {notice && <p className="notice" role="status">{notice}</p>}

    <div className="figures">
      <div className={`figure ${severe === 'CRITICAL' || severe === 'HIGH' ? 'breach' : ''}`}>
        <b>{doc.severity || '—'}</b><span>{t('col.severity')}</span></div>
      <div className={`figure ${findingTone(finding.state) === 'verified' ? 'verified' : ''}`}>
        <b style={{fontSize: 18}}>{label(finding.state)}</b><span>{t('col.state')}</span></div>
      <div className={`figure ${status.tone === 'breach' ? 'breach' : ''}`}>
        <b style={{fontSize: 18}}>{status.label}</b>
        <span>{status.tracked ? t('finding.remediationSla', {n: status.dueDays ?? 0}) : status.open ? t('finding.noSla') : t('finding.resolutionTime')}</span></div>
      <div className="figure"><b style={{fontSize: 18}}>{regression ? <Badge tone={regressionTone(regression.status)}>{regression.status}</Badge> : t('common.none')}</b>
        <span>{t('finding.regression')}</span></div>
    </div>

    <div style={{display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', margin: '4px 0 2px'}}>
      <Badge tone="accent">{t('finding.category')}: {categoryLabel(category.key, t)}</Badge>
      {category.owasp_id && <Badge>
        <a href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noreferrer"
           style={{color: 'inherit', textDecoration: 'none'}} title={t('finding.owasp')}>{owaspLabel(category.owasp_id, t)}</a>
      </Badge>}
    </div>

    <div className="split section">
      <section>
        <div className="panel">
          <h2>{t('finding.reproduction')}</h2>
          {origin ? <>
            <p className="muted" style={{marginTop: -6}}>{t('finding.reproNote', {n: origin.candidate.generation})}</p>
            <dl className="facts">
              <dt>{t('evo.mutations')}</dt><dd>{origin.candidate.lineage.length ? origin.candidate.lineage.join(' → ') : t('evo.seed')}</dd>
              <dt>{t('evo.evidence')}</dt><dd>{origin.candidate.evidence_level === 'heuristic'
                ? t('evo.heuristicOnly') : <strong style={{color: 'var(--breach)'}}>{t('evo.verified')}</strong>}</dd>
              <dt>{t('evo.responseDigest')}</dt><dd className="hash">{origin.candidate.response_hash}</dd>
              <dt>{t('common.from')}</dt><dd><Link href={`/campaigns/${origin.campaign_id}/runs/${origin.run_id}`}>{t('col.run')} {shortId(origin.run_id)}</Link></dd>
            </dl>
            <h3 style={{margin: '14px 0 2px', fontSize: 14}}>{t('finding.attackTrace')}</h3>
            <p className="muted" style={{margin: '0 0 8px'}}>{t('finding.attackTraceNote')}</p>
            <ol className="trace">{(attack_trace.length ? attack_trace : [
              {role: 'attack', label: t('finding.payload'), text: origin.candidate.payload}]).map((step, i) =>
              <li key={i} className={`trace-step trace-${step.role}`}>
                <div className="trace-label">{step.label}</div>
                {step.role === 'attack'
                  ? <pre className="trace-payload">{step.text}</pre>
                  : <p className="trace-text">{step.text}</p>}
                {step.evidence_pattern && <div className="hash trace-evidence">{step.evidence_pattern}</div>}
              </li>)}
            </ol>
          </> : <p className="muted" style={{margin: 0}}>{t('finding.manual')}</p>}
        </div>

        <div className="panel">
          <h2>{t('finding.rootFix')}</h2>
          <dl className="facts">
            <dt>{t('finding.rootCause')}</dt><dd>{doc.root_cause || '—'}</dd>
            <dt>{t('finding.winningMutations')}</dt><dd>{doc.successful_mutations?.join(' → ') || '—'}</dd>
            <dt>{t('finding.evidencePattern')}</dt><dd className="hash">{doc.evidence_pattern || '—'}</dd>
            <dt>{t('finding.fingerprint')}</dt><dd className="hash">{doc.regression_fingerprint || '—'}</dd>
          </dl>
          <div className="notice" style={{marginTop: 12}}><strong>{t('finding.recommendedFix')}</strong> {remediation_detail.summary || doc.remediation || '—'}</div>
          <div className="fix-grid">
            <div>
              <h3 className="fix-head">{t('finding.immediate')}</h3>
              <ul className="fix-list">{remediation_detail.immediate.map((item, i) => <li key={i}>{item}</li>)}</ul>
            </div>
            <div>
              <h3 className="fix-head">{t('finding.longTerm')}</h3>
              <ul className="fix-list">{remediation_detail.long_term.map((item, i) => <li key={i}>{item}</li>)}</ul>
            </div>
          </div>
          <div style={{marginTop: 10}}>
            <Badge tone="accent">{t('finding.guard')}: {remediation_detail.guard} · {remediation_detail.guard_level}</Badge>
          </div>
        </div>

        {regression && <div className="panel">
          <h2>{t('finding.regression')}</h2>
          <p className="muted" style={{marginTop: -6}}>{t('finding.regNote')}</p>
          <dl className="facts">
            <dt>{t('common.status')}</dt><dd><Badge tone={regressionTone(regression.status)}>{regression.status}</Badge></dd>
            <dt>{t('finding.lastReplayed')}</dt><dd>{regression.last_run_at ? when(regression.last_run_at) : t('common.never')}</dd>
          </dl>
          <button disabled={busy} onClick={() => replay(regression.case_id)}>{t('finding.replay')}</button>
        </div>}
      </section>

      <section>
        <div className="panel">
          <h2>{t('finding.activity')}</h2>
          <ol className="timeline">{timeline.length === 0
            ? <li className="muted">{t('finding.noActivity')}</li>
            : timeline.map((entry, i) => <li key={i}>
                <div className="timeline-dot" aria-hidden="true"/>
                <div><strong>{auditLabel(entry.action, t)}</strong>
                  <div className="muted">{when(entry.occurred_at)}</div>
                  {entry.record_hash && <div className="hash" title="Tamper-evident audit hash">{entry.record_hash.slice(0, 23)}…</div>}</div>
              </li>)}
          </ol>
        </div>
        <div className="panel">
          <h2>{t('finding.details')}</h2>
          <dl className="facts">
            <dt>{t('finding.id')}</dt><dd className="hash">{finding.id}</dd>
            <dt>{t('finding.firstSeen')}</dt><dd>{when(finding.created_at)}</dd>
            <dt>{t('finding.lastChange')}</dt><dd>{when(finding.updated_at)}</dd>
            <dt>{t('finding.age')}</dt><dd>{status.ageDays} {t('finding.days')}</dd>
          </dl>
        </div>
        <div className="panel">
          <h2>{t('finding.feedbackQ')}</h2>
          <div className="actions" style={{marginTop: 4}}>
            <button disabled={busy} className={feedback === 'good' ? 'primary' : ''}
              aria-pressed={feedback === 'good'} onClick={() => sendFeedback('good')}>{t('finding.fbGood')}</button>
            <button disabled={busy} className={feedback === 'bad' ? 'danger' : ''}
              aria-pressed={feedback === 'bad'} onClick={() => sendFeedback('bad')}>{t('finding.fbBad')}</button>
            {feedback && <button disabled={busy} onClick={() => sendFeedback('clear')}>{t('finding.fbClear')}</button>}
          </div>
          {feedback && <p className="muted" style={{margin: '8px 0 0'}}>
            {feedback === 'good' ? t('finding.fbGoodSet') : t('finding.fbBadSet')}</p>}
        </div>
      </section>
    </div>
  </>;
}
