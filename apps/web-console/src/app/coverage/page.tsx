'use client';
import Link from 'next/link';
import {useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, Figures, PageHead, RequireWorkspace} from '@/components/ui';
import {control, Coverage, explain} from '@/lib/control';
import {when} from '@/lib/format';

function lastTested(ageDays: number | null): {tone: string; label: string} {
  if (ageDays === null) return {tone: 'signal', label: 'never tested'};
  if (ageDays <= 7) return {tone: 'verified', label: ageDays === 0 ? 'today' : `${ageDays}d ago`};
  if (ageDays <= 14) return {tone: '', label: `${ageDays}d ago`};
  return {tone: 'breach', label: `${ageDays}d ago`};
}

function CoverageBody({workspaceId}: {workspaceId: string}) {
  const [data, setData] = useState<Coverage>();
  const [error, setError] = useState('');
  useEffect(() => {
    setData(undefined); setError('');
    control<Coverage>(`v1/assessments/coverage?workspace_id=${encodeURIComponent(workspaceId)}`)
      .then(setData).catch(e => setError(explain(e)));
  }, [workspaceId]);

  if (error) return <ErrorNote message={error}/>;
  if (!data) return <p className="muted">Loading…</p>;
  const rows = [...data.campaigns].sort((a, b) =>
    Number(b.stale) - Number(a.stale) || (b.age_days ?? 1e9) - (a.age_days ?? 1e9));

  return <>
    <Figures items={[
      {label: 'Targets under test', value: data.campaigns_total},
      {label: 'Scheduled', value: data.scheduled, tone: 'verified'},
      {label: 'Stale (>14d, no schedule)', value: data.stale, tone: data.stale ? 'breach' : ''},
      {label: 'Never run', value: data.never_run, tone: data.never_run ? 'signal' : ''},
      {label: 'Registered agents', value: data.agents_registered},
    ]}/>
    {data.untested_agents > 0 && <p className="notice" style={{marginTop: 16}}>
      <strong>{data.untested_agents}</strong> registered agent{data.untested_agents > 1 ? 's have' : ' has'} no
      campaign yet. <Link href="/campaigns">Create one</Link> to bring them under test.</p>}

    <div className="section">
      {rows.length === 0
        ? <div className="panel"><Empty title="No targets yet">
            <p>Coverage shows which agents are tested and how recently.</p>
            <Link className="button primary" href="/campaigns">Create a campaign</Link></Empty></div>
        : <div className="table-wrap"><table>
            <thead><tr><th>Target</th><th>Environment</th><th>Schedule</th><th>Last tested</th>
              <th className="num">Runs</th><th className="num">Open findings</th></tr></thead>
            <tbody>{rows.map(c => {
              const tested = lastTested(c.age_days);
              return <tr key={c.id}>
                <td><Link href={`/campaigns/${c.id}`}>{c.name}</Link>
                  {c.stale && <> <Badge tone="breach">stale</Badge></>}</td>
                <td>{c.environment_kind}</td>
                <td>{c.scheduled ? <Badge tone="verified">scheduled</Badge> : <span className="muted">manual</span>}</td>
                <td><Badge tone={tested.tone}>{tested.label}</Badge>
                  {c.last_run_at && <div className="hash">{when(c.last_run_at)}</div>}</td>
                <td className="num">{c.runs}</td>
                <td className="num">{c.open_findings ? <Badge tone="breach">{c.open_findings}</Badge> : 0}</td>
              </tr>;
            })}</tbody></table></div>}
    </div>
  </>;
}

export default function CoveragePage() {
  return <>
    <PageHead title="Coverage" description="Which agents are under test and how recently. Stale or untested agents are your blind spots."/>
    <RequireWorkspace>{workspaceId => <CoverageBody key={workspaceId} workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
