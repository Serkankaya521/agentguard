'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {Badge, ErrorNote, PageHead} from '@/components/ui';
import {control, explain, FindingDetail, idempotencyKey} from '@/lib/control';
import {auditLabel, findingTone, regressionTone, shortId, sla, when} from '@/lib/format';

// Mirrors the server's finding workflow; the API still enforces it.
const NEXT: Record<string, [string, string][]> = {
  SUSPECTED: [['VALIDATING', 'Start validation'], ['FALSE_POSITIVE', 'Mark false positive']],
  VALIDATING: [['CONFIRMED', 'Confirm'], ['FALSE_POSITIVE', 'Mark false positive']],
  CONFIRMED: [['FIX_PROPOSED', 'Fix proposed'], ['FALSE_POSITIVE', 'Mark false positive']],
  FIX_PROPOSED: [['RETESTING', 'Start retest']],
  REOPENED: [['FIX_PROPOSED', 'Fix proposed'], ['RETESTING', 'Start retest']],
  FALSE_POSITIVE: [['REOPENED', 'Reopen']],
};
const label = (state: string) => state.toLowerCase().replaceAll('_', ' ');

export default function FindingPage() {
  const {id} = useParams<{id: string}>();
  const [data, setData] = useState<FindingDetail>();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    control<FindingDetail>(`v1/findings/${id}/detail`).then(setData).catch(e => setError(explain(e)));
  }, [id]);
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
    'Replay queued. The regression status updates when the worker finishes.');

  if (!data) return error ? <ErrorNote message={error}/> : <p className="muted">Loading…</p>;
  const {finding, origin, regression, timeline} = data;
  const doc = finding.document;
  const status = sla(doc.severity, finding.state, finding.created_at, finding.updated_at);
  const severe = (doc.severity || '').toUpperCase();

  return <>
    <PageHead title={doc.title || 'Finding'} crumbs={<Link href="/findings">Findings</Link>}
      description={<>{shortId(finding.id)} · first seen {when(finding.created_at)}</>}
      actions={<div className="actions">{(NEXT[finding.state] || []).map(([state, text]) =>
        <button key={state} disabled={busy} className={state === 'FALSE_POSITIVE' ? 'danger' : state === 'CONFIRMED' ? 'primary' : ''}
          onClick={() => transition(state)}>{text}</button>)}</div>}/>
    <ErrorNote message={error}/>
    {notice && <p className="notice" role="status">{notice}</p>}

    <div className="figures">
      <div className={`figure ${severe === 'CRITICAL' || severe === 'HIGH' ? 'breach' : ''}`}>
        <b>{doc.severity || '—'}</b><span>Severity</span></div>
      <div className={`figure ${findingTone(finding.state) === 'verified' ? 'verified' : ''}`}>
        <b style={{fontSize: 18}}>{label(finding.state)}</b><span>State</span></div>
      <div className={`figure ${status.tone === 'breach' ? 'breach' : ''}`}>
        <b style={{fontSize: 18}}>{status.label}</b>
        <span>{status.tracked ? `Remediation SLA ${status.dueDays}d` : status.open ? 'No SLA for this severity' : 'Resolution time'}</span></div>
      <div className="figure"><b style={{fontSize: 18}}>{regression ? <Badge tone={regressionTone(regression.status)}>{regression.status}</Badge> : 'none'}</b>
        <span>Regression</span></div>
    </div>

    <div className="split section">
      <section>
        <div className="panel">
          <h2>Reproduction</h2>
          {origin ? <>
            <p className="muted" style={{marginTop: -6}}>The exact attack that produced this finding. It evolved to generation
              {' '}{origin.candidate.generation} before the agent leaked the canary.</p>
            <dl className="facts">
              <dt>Mutations</dt><dd>{origin.candidate.lineage.length ? origin.candidate.lineage.join(' → ') : 'seed prompt'}</dd>
              <dt>Evidence</dt><dd>{origin.candidate.evidence_level === 'heuristic'
                ? 'heuristic' : <strong style={{color: 'var(--breach)'}}>{origin.candidate.evidence_level} — verified</strong>}</dd>
              <dt>Response digest</dt><dd className="hash">{origin.candidate.response_hash}</dd>
              <dt>From</dt><dd><Link href={`/campaigns/${origin.campaign_id}/runs/${origin.run_id}`}>Run {shortId(origin.run_id)}</Link></dd>
            </dl>
            <h3 style={{margin: '14px 0 6px', fontSize: 14}}>Attack payload</h3>
            <pre className="hash" style={{whiteSpace: 'pre-wrap', margin: 0, background: '#f8f9fb',
              border: '1px solid var(--line-soft)', borderRadius: 6, padding: '10px 12px', maxHeight: 220, overflow: 'auto'}}>{origin.candidate.payload}</pre>
          </> : <p className="muted" style={{margin: 0}}>This finding was recorded manually, without an attack candidate.</p>}
        </div>

        <div className="panel">
          <h2>Root cause and fix</h2>
          <dl className="facts">
            <dt>Root cause</dt><dd>{doc.root_cause || '—'}</dd>
            <dt>Winning mutations</dt><dd>{doc.successful_mutations?.join(' → ') || '—'}</dd>
            <dt>Evidence pattern</dt><dd className="hash">{doc.evidence_pattern || '—'}</dd>
            <dt>Fingerprint</dt><dd className="hash">{doc.regression_fingerprint || '—'}</dd>
          </dl>
          <div className="notice" style={{marginTop: 12}}><strong>Recommended fix.</strong> {doc.remediation || '—'}</div>
        </div>

        {regression && <div className="panel">
          <h2>Regression</h2>
          <p className="muted" style={{marginTop: -6}}>The original exploit, kept as a replayable case. Replay after a fix:
            passed closes the finding as resolved, reopened brings it back.</p>
          <dl className="facts">
            <dt>Status</dt><dd><Badge tone={regressionTone(regression.status)}>{regression.status}</Badge></dd>
            <dt>Last replayed</dt><dd>{regression.last_run_at ? when(regression.last_run_at) : 'never'}</dd>
          </dl>
          <button disabled={busy} onClick={() => replay(regression.case_id)}>Replay exploit</button>
        </div>}
      </section>

      <section>
        <div className="panel">
          <h2>Activity</h2>
          <ol className="timeline">{timeline.length === 0
            ? <li className="muted">No recorded activity.</li>
            : timeline.map((entry, i) => <li key={i}>
                <div className="timeline-dot" aria-hidden="true"/>
                <div><strong>{auditLabel(entry.action)}</strong>
                  <div className="muted">{when(entry.occurred_at)}</div>
                  {entry.record_hash && <div className="hash" title="Tamper-evident audit hash">{entry.record_hash.slice(0, 23)}…</div>}</div>
              </li>)}
          </ol>
        </div>
        <div className="panel">
          <h2>Details</h2>
          <dl className="facts">
            <dt>Finding ID</dt><dd className="hash">{finding.id}</dd>
            <dt>First seen</dt><dd>{when(finding.created_at)}</dd>
            <dt>Last change</dt><dd>{when(finding.updated_at)}</dd>
            <dt>Age</dt><dd>{status.ageDays} days</dd>
          </dl>
        </div>
      </section>
    </div>
  </>;
}
