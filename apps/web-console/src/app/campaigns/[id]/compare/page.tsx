'use client';
import Link from 'next/link';
import {useParams} from 'next/navigation';
import {useCallback, useEffect, useState} from 'react';
import {Badge, ErrorNote, PageHead} from '@/components/ui';
import {Compare, CompareFinding, control, explain, Run} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {categoryLabel, owaspLabel, shortId, VERDICT_TONE, when} from '@/lib/format';

function runOption(run: Run): string {
  return `${shortId(run.id)} · ${run.status}`;
}

function delta(n: number): {text: string; tone: string} {
  if (n > 0) return {text: `+${n}`, tone: 'breach'};
  if (n < 0) return {text: String(n), tone: 'verified'};
  return {text: '0', tone: ''};
}

function FindingList({title, tone, items, t}:
  {title: string; tone: string; items: CompareFinding[]; t: (k: string) => string}) {
  return <section className="panel">
    <h2><Badge tone={tone}>{items.length}</Badge> {title}</h2>
    {items.length === 0 ? <p className="muted" style={{margin: 0}}>{t('compare.noFindings')}</p>
      : <ul className="compare-list">{items.map(f =>
          <li key={f.fingerprint + f.id}>
            <span>{f.title || t('col.finding')}</span>
            <span className="compare-list-tags">
              {f.severity && <Badge tone="breach">{f.severity.toLowerCase()}</Badge>}
              <Badge tone="accent">{categoryLabel(f.category, t)}</Badge>
            </span>
          </li>)}</ul>}
  </section>;
}

export default function ComparePage() {
  const {t} = useT();
  const {id} = useParams<{id: string}>();
  const [runs, setRuns] = useState<Run[]>([]);
  const [base, setBase] = useState('');
  const [head, setHead] = useState('');
  const [data, setData] = useState<Compare>();
  const [error, setError] = useState('');

  // Load the campaign's runs and pick sensible defaults (newest as head, the one
  // before it as base). A ?head= query pre-selects the run the user came from.
  useEffect(() => {
    control<Run[]>(`v1/campaigns/${id}/runs`).then(list => {
      setRuns(list);
      let preset = '';
      try { preset = new URLSearchParams(window.location.search).get('head') || ''; } catch { /* ignore */ }
      const ordered = [...list].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
      const newest = preset || ordered[0]?.id || '';
      const prior = ordered.find(r => r.id !== newest)?.id || '';
      setHead(newest); setBase(prior);
    }).catch(e => setError(explain(e)));
  }, [id]);

  const compare = useCallback(() => {
    if (!base || !head || base === head) { setData(undefined); return; }
    setError('');
    control<Compare>(`v1/campaigns/${id}/compare?base=${base}&head=${head}`)
      .then(setData).catch(e => { setData(undefined); setError(explain(e)); });
  }, [id, base, head]);
  useEffect(compare, [compare]);

  const metrics: {label: string; key: 'verified_findings' | 'open_findings' | 'requests'}[] = [
    {label: t('compare.verified'), key: 'verified_findings'},
    {label: t('compare.openFindings'), key: 'open_findings'},
    {label: t('compare.requests'), key: 'requests'},
  ];

  return <>
    <PageHead title={t('compare.title')} description={t('compare.desc')}
      crumbs={<><Link href="/campaigns">{t('nav.campaigns')}</Link> / <Link href={`/campaigns/${id}`}>{shortId(id)}</Link></>}/>
    <ErrorNote message={error}/>

    <div className="compare-pickers">
      <label>{t('compare.base')}
        <select value={base} onChange={e => setBase(e.target.value)}>
          <option value="">—</option>
          {runs.map(r => <option key={r.id} value={r.id}>{runOption(r)}</option>)}
        </select>
      </label>
      <button className="compare-swap" onClick={() => { const b = base; setBase(head); setHead(b); }}
        aria-label={t('compare.swap')}>⇄</button>
      <label>{t('compare.head')}
        <select value={head} onChange={e => setHead(e.target.value)}>
          <option value="">—</option>
          {runs.map(r => <option key={r.id} value={r.id}>{runOption(r)}</option>)}
        </select>
      </label>
    </div>

    {!data ? <div className="panel"><p className="muted" style={{margin: 0}}>{t('compare.pick')}</p></div> : <>
      <div className="split section">
        <div className={`verdict ${VERDICT_TONE[data.base.verdict]}`}>
          <span className="verdict-dot" aria-hidden="true"/>
          <div><strong>{t('compare.base')} · {shortId(data.base.run_id)}</strong>
            <p>{t(`verdict.${data.base.verdict}.t`)} · {when(data.base.completed_at)}</p></div>
        </div>
        <div className={`verdict ${VERDICT_TONE[data.head.verdict]}`}>
          <span className="verdict-dot" aria-hidden="true"/>
          <div><strong>{t('compare.head')} · {shortId(data.head.run_id)}</strong>
            <p>{t(`verdict.${data.head.verdict}.t`)} · {when(data.head.completed_at)}</p></div>
        </div>
      </div>

      <section className="section">
        <div className="table-wrap"><table>
          <thead><tr><th>{t('compare.metric')}</th><th className="num">{t('compare.base')}</th>
            <th className="num">{t('compare.head')}</th><th className="num">{t('compare.delta')}</th></tr></thead>
          <tbody>{metrics.map(m => {
            const d = delta(data.delta[m.key]);
            return <tr key={m.key}>
              <td>{m.label}</td>
              <td className="num">{data.base[m.key]}</td>
              <td className="num">{data.head[m.key]}</td>
              <td className="num"><Badge tone={d.tone}>{d.text}</Badge></td>
            </tr>;
          })}</tbody>
        </table></div>
      </section>

      {data.categories.length > 0 && <section className="section">
        <h2>{t('compare.byCategory')}</h2>
        <div className="table-wrap"><table>
          <thead><tr><th>{t('col.category')}</th><th>{t('col.owasp')}</th><th className="num">{t('compare.base')}</th>
            <th className="num">{t('compare.head')}</th><th className="num">{t('compare.delta')}</th></tr></thead>
          <tbody>{data.categories.map(c => {
            const d = delta(c.delta);
            return <tr key={c.key}>
              <td>{categoryLabel(c.key, t)}</td>
              <td>{c.owasp_id ? owaspLabel(c.owasp_id, t) : '—'}</td>
              <td className="num">{c.base}</td><td className="num">{c.head}</td>
              <td className="num"><Badge tone={d.tone}>{d.text}</Badge></td>
            </tr>;
          })}</tbody>
        </table></div>
      </section>}

      <div className="compare-findings section">
        <FindingList title={t('compare.fixed')} tone="verified" items={data.findings.fixed} t={t}/>
        <FindingList title={t('compare.new')} tone="breach" items={data.findings.new} t={t}/>
        <FindingList title={t('compare.persisting')} tone="signal" items={data.findings.persisting} t={t}/>
      </div>
    </>}
  </>;
}
