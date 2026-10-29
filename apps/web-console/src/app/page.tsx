'use client';
import Link from 'next/link';
import {useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, Figures, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Overview} from '@/lib/control';
import {runTone, score, when} from '@/lib/format';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function OverviewBody({workspaceId}: {workspaceId: string}) {
  const [data, setData] = useState<Overview>();
  const [error, setError] = useState('');
  useEffect(() => {
    setData(undefined); setError('');
    control<Overview>(`v1/assessments/overview?workspace_id=${encodeURIComponent(workspaceId)}`)
      .then(setData).catch(e => setError(explain(e)));
  }, [workspaceId]);

  if (error) return <ErrorNote message={error}/>;
  if (!data) return <p className="muted">Loading…</p>;
  const open = Object.values(data.open_findings_by_severity).reduce((a, b) => a + b, 0);
  const reopened = data.regressions.reopened || 0;
  return <>
    <Figures items={[
      {label: 'Open verified findings', value: open, tone: open ? 'breach' : 'verified'},
      {label: 'Regressions passing', value: data.regressions.passed || 0, tone: 'verified'},
      {label: 'Regressions reopened', value: reopened, tone: reopened ? 'breach' : ''},
      {label: 'Runs in last 30 days', value: data.runs_30d.total},
      {label: 'Requests sent to targets', value: data.runs_30d.requests.toLocaleString()},
    ]}/>
    <div className="split section">
      <section>
        <h2>Recent runs</h2>
        {data.recent_runs.length === 0
          ? <div className="panel"><Empty title="No runs yet"><p>Create a campaign and start a run to test an agent.</p>
              <Link className="button primary" href="/campaigns">Create a campaign</Link></Empty></div>
          : <div className="table-wrap"><table>
              <thead><tr><th>Campaign</th><th>Status</th><th className="num">Requests</th>
                <th className="num">Findings</th><th className="num">Best score</th><th>Started</th></tr></thead>
              <tbody>{data.recent_runs.map(run => <tr key={run.id}>
                <td><Link href={`/campaigns/${run.campaign_id}/runs/${run.id}`}>{run.campaign_name}</Link></td>
                <td><Badge tone={runTone(run.status)}>{run.status}</Badge></td>
                <td className="num">{run.candidates_evaluated}</td>
                <td className="num">{run.findings_created ? <Badge tone="breach">{run.findings_created}</Badge> : 0}</td>
                <td className="num">{score(run.best_score)}</td>
                <td>{when(run.created_at)}</td>
              </tr>)}</tbody></table></div>}
      </section>
      <section>
        <h2>Open findings by severity</h2>
        <div className="panel">{open === 0
          ? <p className="muted" style={{margin: 0}}>No open verified findings in this workspace.</p>
          : <dl className="facts">{SEVERITIES.filter(s => data.open_findings_by_severity[s]).map(s =>
              <div key={s} style={{display: 'contents'}}><dt>{s.toLowerCase()}</dt>
                <dd><Link href="/findings">{data.open_findings_by_severity[s]}</Link></dd></div>)}</dl>}
        </div>
        <div className="panel">
          <dl className="facts">
            <dt>Campaigns</dt><dd>{data.campaigns.total} ({data.campaigns.active} scheduled)</dd>
            <dt>Failed runs (30d)</dt><dd>{data.runs_30d.failed}</dd>
            <dt>Last completed</dt><dd>{when(data.runs_30d.last_completed_at)}</dd>
          </dl>
        </div>
      </section>
    </div>
  </>;
}

export default function Home() {
  return <>
    <PageHead title="Overview" description="Verified weaknesses in your AI agents, and whether fixes are holding."
      actions={<Link className="button primary" href="/campaigns">New campaign</Link>}/>
    <RequireWorkspace>{workspaceId => <OverviewBody workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
