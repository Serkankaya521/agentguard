'use client';
import {useEffect, useState} from 'react';
import {Badge, Empty, ErrorNote, Figures, PageHead, RequireWorkspace} from '@/components/ui';
import {control, explain, GuardEvents, GuardSetting, GuardSettings} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {shortId, when} from '@/lib/format';

function matchLabel(key: string, t: (k: string) => string): string {
  const label = t(`match.${key}`);
  return label === `match.${key}` ? key : label;
}

const MODES: GuardSetting['mode'][] = ['off', 'shadow', 'enforce'];
const ACTIONS: GuardSetting['action'][] = ['mask', 'stop'];

type Draft = GuardSetting & {saving?: boolean; saved?: boolean};

function GuardSettingsPanel({workspaceId}: {workspaceId: string}) {
  const {t} = useT();
  const [rows, setRows] = useState<Draft[]>();
  const [error, setError] = useState('');

  useEffect(() => {
    setRows(undefined); setError('');
    control<GuardSettings>(`v1/runtime/guard-settings?workspace_id=${encodeURIComponent(workspaceId)}`)
      .then(r => setRows(r.settings)).catch(e => setError(explain(e)));
  }, [workspaceId]);

  function edit(envId: string, patch: Partial<Draft>) {
    setRows(prev => prev?.map(r => r.environment_id === envId ? {...r, ...patch, saved: false} : r));
  }
  async function save(row: Draft) {
    edit(row.environment_id, {saving: true});
    try {
      const saved = await control<GuardSetting>(`v1/runtime/guard-settings/${row.environment_id}`,
        {method: 'PUT', body: JSON.stringify({mode: row.mode, action: row.action})});
      setRows(prev => prev?.map(r => r.environment_id === row.environment_id
        ? {...r, ...saved, saving: false, saved: true} : r));
    } catch (e) { setError(explain(e)); edit(row.environment_id, {saving: false}); }
  }

  if (error) return <ErrorNote message={error}/>;
  if (!rows) return <p className="muted">{t('common.loading')}</p>;

  return <section className="panel section">
    <h2 style={{marginBottom: 2}}>{t('guard.settings')}</h2>
    <p className="muted" style={{marginTop: 0}}>{t('guard.settingsNote')}</p>
    {rows.length === 0 ? <p className="muted" style={{margin: 0}}>{t('guard.noEnvs')}</p>
      : <div className="table-wrap"><table>
        <thead><tr><th>{t('col.environment')}</th><th>{t('col.mode')}</th><th>{t('guard.action')}</th><th/></tr></thead>
        <tbody>{rows.map(row => <tr key={row.environment_id}>
          <td>{row.environment_name} <span className="hash">{row.environment_kind}</span>
            {!row.configured && <> <Badge>{t('guard.default')}</Badge></>}</td>
          <td><select value={row.mode} aria-label={t('col.mode')}
            onChange={e => edit(row.environment_id, {mode: e.target.value as GuardSetting['mode']})}>
            {MODES.map(m => <option key={m} value={m}>{t(`mode.${m}`)}</option>)}</select></td>
          <td><select value={row.action} aria-label={t('guard.action')} disabled={row.mode !== 'enforce'}
            onChange={e => edit(row.environment_id, {action: e.target.value as GuardSetting['action']})}>
            {ACTIONS.map(a => <option key={a} value={a}>{t(`action.${a}`)}</option>)}</select></td>
          <td style={{whiteSpace: 'nowrap'}}>
            <button className="primary" disabled={row.saving} onClick={() => save(row)}>
              {row.saving ? t('common.loading') : t('guard.save')}</button>
            {row.saved && <span className="muted" style={{marginLeft: 8}}>{t('guard.saved')}</span>}</td>
        </tr>)}</tbody></table></div>}
  </section>;
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

    <GuardSettingsPanel workspaceId={workspaceId}/>

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
