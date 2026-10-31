'use client';
import {useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, Figures, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, GuardEvents} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {shortId, when} from '@/lib/format';

function matchLabel(key: string, t: (k: string) => string): string {
  const label = t(`match.${key}`);
  return label === `match.${key}` ? key : label;
}

function GuardBody({workspaceId}: {workspaceId: string}) {
  const {t} = useT();
  const [data, setData] = useState<GuardEvents>();
  const [error, setError] = useState('');
  useEffect(() => {
    setData(undefined); setError('');
    control<GuardEvents>(`v1/runtime/guard-events?workspace_id=${encodeURIComponent(workspaceId)}&limit=100`)
      .then(setData).catch(e => setError(explain(e)));
  }, [workspaceId]);

  if (error) return <ErrorNote message={error}/>;
  if (!data) return <p className="muted">{t('common.loading')}</p>;
  const {summary, events} = data;

  return <>
    <Figures items={[
      {label: t('guard.total'), value: summary.total},
      {label: t('guard.wouldBlock'), value: summary.would_block, tone: summary.would_block ? 'breach' : ''},
      {label: t('guard.applied'), value: summary.applied, tone: summary.applied ? 'verified' : ''},
      {label: t('guard.shadow'), value: summary.shadow, tone: summary.shadow ? 'signal' : ''},
      {label: t('guard.enforce'), value: summary.enforce},
    ]}/>

    <div className="verdict signal" style={{marginTop: 20}}>
      <span className="verdict-dot" aria-hidden="true"/>
      <div><strong>{t('guard.shadow')} / {t('guard.enforce')}</strong><p>{t('guard.modeNote')}</p></div>
    </div>

    <section className="section">
      <div style={{display: 'flex', gap: 14, flexWrap: 'wrap', color: 'var(--muted)', fontSize: 13, marginBottom: 12}}>
        <span>{t('guard.last7')}: <strong>{summary.last_7d}</strong></span>
        <span>{t('guard.last30')}: <strong>{summary.last_30d}</strong></span>
        <span>{t('guard.lastEvent')}: <strong>{summary.last_event_at ? when(summary.last_event_at) : t('common.never')}</strong></span>
      </div>

      {events.length === 0
        ? <div className="panel"><Empty title={t('guard.none')}><p>{t('guard.noneBody')}</p></Empty></div>
        : <><h2 style={{marginBottom: 10}}>{t('guard.recent')}</h2>
          <div className="table-wrap"><table>
            <thead><tr><th>{t('col.time')}</th><th>{t('col.mode')}</th><th>{t('col.result')}</th>
              <th>{t('col.match')}</th><th>{t('col.severity')}</th><th>{t('col.source')}</th></tr></thead>
            <tbody>{events.map(ev => {
              const result = ev.applied ? {tone: 'verified', key: 'guard.resBlocked'}
                : ev.would_block ? {tone: 'breach', key: 'guard.resWouldBlock'}
                : {tone: '', key: 'guard.resPassed'};
              return <tr key={ev.id}>
                <td>{when(ev.occurred_at)}</td>
                <td><Badge tone={ev.mode === 'enforce' ? 'verified' : 'signal'}>{t(`mode.${ev.mode}`)}</Badge></td>
                <td><Badge tone={result.tone}>{t(result.key)}</Badge></td>
                <td>{matchLabel(ev.match_type, t)}</td>
                <td className="hash">{ev.severity}</td>
                <td className="hash">{ev.agent_id ? shortId(ev.agent_id) : ev.trace_id ? shortId(ev.trace_id) : '—'}</td>
              </tr>;
            })}</tbody></table></div></>}
    </section>
  </>;
}

export default function RuntimeGuardPage() {
  const {t} = useT();
  return <>
    <PageHead title={t('guard.title')} description={t('guard.desc')}/>
    <RequireWorkspace>{workspaceId => <GuardBody workspaceId={workspaceId}/>}</RequireWorkspace>
  </>;
}
