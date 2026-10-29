'use client';
import {useEffect, useState} from 'react';
import {ErrorNote, PageHead} from '@/components/ui';
import {control, explain, Row} from '@/lib/control';
import {useT} from '@/lib/i18n';

function Facts({data}: {data?: Row}) {
  if (!data) return <p className="muted">—</p>;
  return <dl className="facts">{Object.entries(data).filter(([k]) => k !== 'tenant_id').map(([key, value]) =>
    <div key={key} style={{display: 'contents'}}><dt>{key.replaceAll('_', ' ')}</dt>
      <dd>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</dd></div>)}</dl>;
}

export default function Operations() {
  const {t} = useT();
  const [limits, setLimits] = useState<Row>();
  const [usage, setUsage] = useState<Row[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    Promise.all([control<Row>('v1/platform/limits'), control<Row[]>('v1/platform/usage')])
      .then(([l, u]) => { setLimits(l); setUsage(u); }).catch(e => setError(explain(e)));
  }, []);
  return <>
    <PageHead title={t('ops.title')} description={t('ops.desc')}/>
    <ErrorNote message={error}/>
    <div className="split">
      <section className="panel"><h2>{t('ops.limits')}</h2><Facts data={limits}/></section>
      <section className="panel"><h2>{t('ops.recentUsage')}</h2>{usage.length
        ? <table><thead><tr><th>{t('ops.date')}</th><th>{t('ops.metric')}</th><th className="num">{t('ops.amount')}</th></tr></thead>
            <tbody>{usage.slice(0, 30).map((row, i) => <tr key={i}><td>{String(row.usage_date)}</td>
              <td>{String(row.metric).replaceAll('_', ' ')}</td><td className="num">{String(row.amount)}</td></tr>)}</tbody></table>
        : <p className="muted">{t('ops.noUsage')}</p>}</section>
    </div>
  </>;
}
