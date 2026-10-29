'use client';
import Link from 'next/link';
import {useEffect, useState} from 'react';
import {TrendChart, TrendLegend} from '@/components/trend-chart';
import {Badge, Empty, ErrorNote, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Overview} from '@/lib/control';
import {runTone, score, when} from '@/lib/format';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function postureTone(value: number): {tone: string; label: string} {
  if (value >= 90) return {tone: 'verified', label: 'Strong'};
  if (value >= 70) return {tone: 'signal', label: 'Needs attention'};
  return {tone: 'breach', label: 'At risk'};
}

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
  const {posture} = data;
  const grade = postureTone(posture.score);
  const slaPct = posture.sla_compliance === null ? '—' : `${Math.round(posture.sla_compliance * 100)}%`;
  const hasTrend = data.trend.some(w => w.runs || w.found || w.resolved);

  return <>
    <div className="posture">
      <div className={`posture-score ${grade.tone}`}>
        <span className="posture-num">{posture.score}</span>
        <span className="posture-grade">{grade.label}</span>
        <span className="muted">Security posture</span>
      </div>
      <div className="figures posture-figures">
        <div className={`figure ${posture.open_findings ? 'breach' : 'verified'}`}>
          <b>{posture.open_findings}</b><span>Open findings</span></div>
        <div className="figure"><b>{posture.mttr_days === null ? '—' : `${posture.mttr_days}d`}</b>
          <span>Mean time to remediate</span></div>
        <div className={`figure ${posture.sla_breached ? 'signal' : ''}`}><b>{slaPct}</b>
          <span>SLA compliance ({posture.resolved_total} resolved)</span></div>
        <div className="figure"><b>{data.runs_30d.total}</b><span>Runs (30d)</span></div>
      </div>
    </div>

    <div className="split section">
      <section className="panel">
        <h2>Activity (8 weeks)</h2>
        {hasTrend ? <><TrendChart data={data.trend}/><TrendLegend/></>
          : <p className="muted" style={{margin: 0}}>No runs in this window yet.</p>}
      </section>
      <section className="panel">
        <h2>Open findings by severity</h2>
        {posture.open_findings === 0
          ? <p className="muted" style={{margin: 0}}>No open verified findings.</p>
          : <dl className="facts">{SEVERITIES.filter(s => data.open_findings_by_severity[s]).map(s =>
              <div key={s} style={{display: 'contents'}}>
                <dt><Badge tone={s === 'CRITICAL' || s === 'HIGH' ? 'breach' : 'signal'}>{s.toLowerCase()}</Badge></dt>
                <dd><Link href="/findings">{data.open_findings_by_severity[s]} open</Link></dd></div>)}</dl>}
        <dl className="facts" style={{marginTop: 14}}>
          <dt>Regressions passing</dt><dd>{data.regressions.passed || 0}</dd>
          <dt>Regressions reopened</dt><dd>{data.regressions.reopened || 0}</dd>
          <dt>Campaigns</dt><dd>{data.campaigns.total} ({data.campaigns.active} scheduled)</dd>
        </dl>
      </section>
    </div>

    <section className="section">
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
  </>;
}

export default function Home() {
  return <>
    <PageHead title="Overview" description="Your agents' security posture, remediation performance and recent testing."
      actions={<Link className="button primary" href="/campaigns">New campaign</Link>}/>
    <RequireWorkspace>{workspaceId => <OverviewBody workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
