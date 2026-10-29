'use client';
import Link from 'next/link';
import {useCallback, useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Finding} from '@/lib/control';
import {findingTone, shortId, sla, when} from '@/lib/format';

// Mirrors the server's allowed workflow so only valid buttons are shown; the API still enforces it.
const NEXT: Record<string, [string, string][]> = {
  SUSPECTED: [['VALIDATING', 'Start validation'], ['FALSE_POSITIVE', 'Mark false positive']],
  VALIDATING: [['CONFIRMED', 'Confirm'], ['FALSE_POSITIVE', 'Mark false positive']],
  CONFIRMED: [['FIX_PROPOSED', 'Fix proposed'], ['FALSE_POSITIVE', 'Mark false positive']],
  FIX_PROPOSED: [['RETESTING', 'Start retest']],
  REOPENED: [['FIX_PROPOSED', 'Fix proposed'], ['RETESTING', 'Start retest']],
  FALSE_POSITIVE: [['REOPENED', 'Reopen']],
};
const SEVERITY_RANK: Record<string, number> = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3};
const label = (state: string) => state.toLowerCase().replaceAll('_', ' ');

function FindingTable({workspaceId}: {workspaceId: string}) {
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

  if (!rows) return error ? <ErrorNote message={error}/> : <p className="muted">Loading…</p>;
  const closed = (f: Finding) => f.state === 'RESOLVED_VERIFIED' || f.state === 'FALSE_POSITIVE';
  const visible = rows.filter(f => showClosed || !closed(f)).sort((a, b) =>
    Number(closed(a)) - Number(closed(b)) ||
    (SEVERITY_RANK[a.document.severity || ''] ?? 9) - (SEVERITY_RANK[b.document.severity || ''] ?? 9) ||
    b.created_at.localeCompare(a.created_at));

  return <>
    <ErrorNote message={error}/>
    <label className="field check" style={{marginBottom: 12}}>
      <input type="checkbox" checked={showClosed} onChange={e => setShowClosed(e.target.checked)}/>
      Show resolved and false positives ({rows.filter(closed).length})
    </label>
    {visible.length === 0
      ? <div className="panel"><Empty title={rows.length ? 'No open findings' : 'No findings yet'}>
          {rows.length ? 'Every finding is resolved or dismissed.' : 'Findings appear when a campaign run captures target-side evidence.'}
        </Empty></div>
      : <div className="table-wrap"><table>
          <thead><tr><th>Finding</th><th>Severity</th><th>State</th><th>SLA</th><th>Source</th><th>Next step</th></tr></thead>
          <tbody>{visible.map(f => {
            const status = sla(f.document.severity, f.state, f.created_at, f.updated_at);
            return <tr key={f.id}>
              <td><Link href={`/findings/${f.id}`}><strong>{f.document.title || 'Finding'}</strong></Link>
                <div className="hash">{shortId(f.id)} · {when(f.created_at)}</div></td>
              <td>{f.document.severity ? <Badge tone={SEVERITY_RANK[f.document.severity] <= 1 ? 'breach' : 'signal'}>{f.document.severity.toLowerCase()}</Badge> : '—'}</td>
              <td><Badge tone={findingTone(f.state)}>{label(f.state)}</Badge></td>
              <td>{status.tone ? <Badge tone={status.tone}>{status.label}</Badge> : <span className="muted">{status.label}</span>}</td>
              <td>{f.document.campaign_id && f.document.run_id
                ? <Link href={`/campaigns/${f.document.campaign_id}/runs/${f.document.run_id}`}>Run {shortId(f.document.run_id)}</Link>
                : 'manual'}</td>
              <td><div className="actions">{(NEXT[f.state] || []).map(([state, text]) =>
                <button key={state} disabled={busy === f.id} className={state === 'FALSE_POSITIVE' ? 'danger' : ''}
                  onClick={() => transition(f, state)}>{text}</button>)}
                {f.state === 'RETESTING' && <Link href={`/findings/${f.id}`} className="muted">Replay to close →</Link>}
              </div></td>
            </tr>;
          })}</tbody></table></div>}
  </>;
}

export default function Findings() {
  return <>
    <PageHead title="Findings" description="Weaknesses confirmed by target-side evidence, and where each one is in the fix cycle."/>
    <RequireWorkspace>{workspaceId => <FindingTable key={workspaceId} workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
