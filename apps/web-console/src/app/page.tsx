'use client';
import Link from 'next/link';
import {useEffect, useState} from 'react';
import {TrendChart, TrendLegend} from '@/components/trend-chart';
import {Badge, Empty, ErrorNote, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, Overview} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {categoryLabel, owaspLabel, runTone, score, when} from '@/lib/format';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function OverviewBody({workspaceId}: {workspaceId: string}) {
  const {t} = useT();
  const postureTone = (value: number) => value >= 90 ? {tone: 'verified', label: t('overview.strong')}
    : value >= 70 ? {tone: 'signal', label: t('overview.attention')} : {tone: 'breach', label: t('overview.atRisk')};
  const [data, setData] = useState<Overview>();
  const [error, setError] = useState('');
  useEffect(() => {
    setData(undefined); setError('');
    control<Overview>(`v1/assessments/overview?workspace_id=${encodeURIComponent(workspaceId)}`)
      .then(setData).catch(e => setError(explain(e)));
  }, [workspaceId]);

  if (error) return <ErrorNote message={error}/>;
  if (!data) return <p className="muted">{t('common.loading')}</p>;
  const {posture} = data;
  const grade = postureTone(posture.score);
  const slaPct = posture.sla_compliance === null ? '—' : `${Math.round(posture.sla_compliance * 100)}%`;
  const hasTrend = data.trend.some(w => w.runs || w.found || w.resolved);

  return <>
    <div className="posture">
      <div className={`posture-score ${grade.tone}`}>
        <span className="posture-num">{posture.score}</span>
        <span className="posture-grade">{grade.label}</span>
        <span className="muted">{t('overview.posture')}</span>
      </div>
      <div className="figures posture-figures">
        <div className={`figure ${posture.open_findings ? 'breach' : 'verified'}`}>
          <b>{posture.open_findings}</b><span>{t('overview.openFindings')}</span></div>
        <div className="figure"><b>{posture.mttr_days === null ? '—' : `${posture.mttr_days}${t('unit.dayShort')}`}</b>
          <span>{t('overview.mttr')}</span></div>
        <div className={`figure ${posture.sla_breached ? 'signal' : ''}`}><b>{slaPct}</b>
          <span>{t('overview.slaCompliance')} ({posture.resolved_total} {t('overview.resolved')})</span></div>
        <div className="figure"><b>{data.runs_30d.total}</b><span>{t('overview.runs30')}</span></div>
      </div>
    </div>

    <div className="split section">
      <section className="panel">
        <h2>{t('overview.activity')}</h2>
        {hasTrend ? <><TrendChart data={data.trend}/><TrendLegend/></>
          : <p className="muted" style={{margin: 0}}>{t('overview.noActivity')}</p>}
      </section>
      <section className="panel">
        <h2>{t('overview.openBySeverity')}</h2>
        {posture.open_findings === 0
          ? <p className="muted" style={{margin: 0}}>{t('overview.noOpen')}</p>
          : <dl className="facts">{SEVERITIES.filter(s => data.open_findings_by_severity[s]).map(s =>
              <div key={s} style={{display: 'contents'}}>
                <dt><Badge tone={s === 'CRITICAL' || s === 'HIGH' ? 'breach' : 'signal'}>{s.toLowerCase()}</Badge></dt>
                <dd><Link href="/findings">{data.open_findings_by_severity[s]} {t('overview.open')}</Link></dd></div>)}</dl>}
        <dl className="facts" style={{marginTop: 14}}>
          <dt>{t('overview.regPassing')}</dt><dd>{data.regressions.passed || 0}</dd>
          <dt>{t('overview.regReopened')}</dt><dd>{data.regressions.reopened || 0}</dd>
          <dt>{t('overview.campaignsLine')}</dt><dd>{data.campaigns.total} ({data.campaigns.active} {t('overview.scheduled')})</dd>
        </dl>
      </section>
    </div>

    {data.open_findings_by_category.length > 0 && (() => {
      const top = data.open_findings_by_category[0].count || 1;
      return <section className="section panel">
        <h2>{t('overview.openByCategory')}</h2>
        <div className="cat-bars">{data.open_findings_by_category.map(row =>
          <div key={row.key} className="cat-bar">
            <div className="cat-bar-head">
              <Link href="/findings">{categoryLabel(row.key, t)}</Link>
              {row.owasp_id && <Badge>{owaspLabel(row.owasp_id, t)}</Badge>}
              <span className="cat-bar-count">{row.count}</span>
            </div>
            <div className="cat-bar-track"><span className="cat-bar-fill"
              style={{width: `${Math.round((row.count / top) * 100)}%`}}/></div>
          </div>)}</div>
        <p className="muted" style={{margin: '10px 0 0', fontSize: 12}}>{t('overview.owaspNote')}</p>
      </section>;
    })()}

    <section className="section panel">
      <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12}}>
        <h2 style={{marginBottom: 0}}>{t('overview.runtimeDefense')}</h2>
        <Link className="button" href="/runtime-guard">{t('overview.viewGuard')}</Link>
      </div>
      {data.runtime_guard.events_30d === 0
        ? <p className="muted" style={{margin: '10px 0 0'}}>{t('overview.guardQuiet')}</p>
        : <div className="figures" style={{marginTop: 12}}>
            <div className="figure"><b>{data.runtime_guard.events_30d}</b><span>{t('overview.guardEvents')}</span></div>
            <div className={`figure ${data.runtime_guard.would_block_30d ? 'breach' : ''}`}>
              <b>{data.runtime_guard.would_block_30d}</b><span>{t('overview.guardWouldBlock')}</span></div>
            <div className={`figure ${data.runtime_guard.applied_30d ? 'verified' : ''}`}>
              <b>{data.runtime_guard.applied_30d}</b><span>{t('overview.guardEnforced')}</span></div>
          </div>}
    </section>

    <section className="section">
      <h2>{t('overview.recentRuns')}</h2>
      {data.recent_runs.length === 0
        ? <div className="panel"><Empty title={t('overview.noRuns')}><p>{t('overview.noRunsBody')}</p>
            <Link className="button primary" href="/campaigns">{t('overview.createCampaign')}</Link></Empty></div>
        : <div className="table-wrap"><table>
            <thead><tr><th>{t('col.campaign')}</th><th>{t('common.status')}</th><th className="num">{t('col.requests')}</th>
              <th className="num">{t('col.findings')}</th><th className="num">{t('col.bestScore')}</th><th>{t('col.started')}</th></tr></thead>
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

function OverviewHead() {
  const {t} = useT();
  return <PageHead title={t('overview.title')} description={t('overview.desc')}
    actions={<Link className="button primary" href="/campaigns">{t('overview.newCampaign')}</Link>}/>;
}

export default function Home() {
  return <>
    <OverviewHead/>
    <RequireWorkspace>{workspaceId => <OverviewBody workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
