'use client';
import Link from 'next/link';
import {useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, Figures, PageHead, RequireWorkspace} from '@/components/ui';
import {control, Coverage, explain} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {when} from '@/lib/format';

function CoverageBody({workspaceId}: {workspaceId: string}) {
  const {t} = useT();
  const lastTested = (ageDays: number | null): {tone: string; label: string} => {
    if (ageDays === null) return {tone: 'signal', label: t('cov.neverTested')};
    if (ageDays === 0) return {tone: 'verified', label: t('common.today')};
    const label = t('cov.ago', {n: ageDays});
    if (ageDays <= 7) return {tone: 'verified', label};
    if (ageDays <= 14) return {tone: '', label};
    return {tone: 'breach', label};
  };
  const [data, setData] = useState<Coverage>();
  const [error, setError] = useState('');
  useEffect(() => {
    setData(undefined); setError('');
    control<Coverage>(`v1/assessments/coverage?workspace_id=${encodeURIComponent(workspaceId)}`)
      .then(setData).catch(e => setError(explain(e)));
  }, [workspaceId]);

  if (error) return <ErrorNote message={error}/>;
  if (!data) return <p className="muted">{t('common.loading')}</p>;
  const rows = [...data.campaigns].sort((a, b) =>
    Number(b.stale) - Number(a.stale) || (b.age_days ?? 1e9) - (a.age_days ?? 1e9));

  return <>
    <Figures items={[
      {label: t('cov.targets'), value: data.campaigns_total},
      {label: t('cov.scheduled'), value: data.scheduled, tone: 'verified'},
      {label: t('cov.stale'), value: data.stale, tone: data.stale ? 'breach' : ''},
      {label: t('cov.neverRun'), value: data.never_run, tone: data.never_run ? 'signal' : ''},
      {label: t('cov.registered'), value: data.agents_registered},
    ]}/>
    {data.untested_agents > 0 && <p className="notice" style={{marginTop: 16}}>
      {t('cov.untested', {n: data.untested_agents})} <Link href="/campaigns">{t('cov.createOne')}</Link> {t('cov.bringUnderTest')}</p>}

    <div className="section">
      {rows.length === 0
        ? <div className="panel"><Empty title={t('cov.noneTitle')}>
            <p>{t('cov.noneBody')}</p>
            <Link className="button primary" href="/campaigns">{t('overview.createCampaign')}</Link></Empty></div>
        : <div className="table-wrap"><table>
            <thead><tr><th>{t('col.target')}</th><th>{t('col.environment')}</th><th>{t('col.schedule')}</th><th>{t('col.lastTested')}</th>
              <th className="num">{t('campaign.runs')}</th><th className="num">{t('col.openFindings')}</th></tr></thead>
            <tbody>{rows.map(c => {
              const tested = lastTested(c.age_days);
              return <tr key={c.id}>
                <td><Link href={`/campaigns/${c.id}`}>{c.name}</Link>
                  {c.stale && <> <Badge tone="breach">{t('cov.staleBadge')}</Badge></>}</td>
                <td>{c.environment_kind}</td>
                <td>{c.scheduled ? <Badge tone="verified">{t('cov.scheduled').toLowerCase()}</Badge> : <span className="muted">{t('common.manual')}</span>}</td>
                <td><Badge tone={tested.tone}>{tested.label}</Badge>
                  {c.last_run_at && <div className="hash">{when(c.last_run_at)}</div>}</td>
                <td className="num">{c.runs}</td>
                <td className="num">{c.open_findings ? <Badge tone="breach">{c.open_findings}</Badge> : 0}</td>
              </tr>;
            })}</tbody></table></div>}
    </div>
  </>;
}

function CoverageHead() {
  const {t} = useT();
  return <PageHead title={t('cov.title')} description={t('cov.desc')}/>;
}

export default function CoveragePage() {
  return <>
    <CoverageHead/>
    <RequireWorkspace>{workspaceId => <CoverageBody key={workspaceId} workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
