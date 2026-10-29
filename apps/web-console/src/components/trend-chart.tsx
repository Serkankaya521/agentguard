'use client';
import {useId} from 'react';

type Point = {week: string; runs: number; found: number; resolved: number};

/** Inline SVG so it works under a self-only CSP. Grouped weekly bars:
 *  findings found vs findings resolved, with a runs line overlaid. */
export function TrendChart({data}: {data: Point[]}) {
  const clip = useId();
  const W = 680, H = 180, padX = 36, padY = 16, base = H - 26;
  const max = Math.max(1, ...data.flatMap(d => [d.found, d.resolved, d.runs]));
  const step = (W - padX * 2) / Math.max(1, data.length);
  const barW = Math.min(16, step / 3);
  const y = (v: number) => base - (v / max) * (base - padY);
  const x = (i: number) => padX + step * i + step / 2;
  const line = data.map((d, i) => `${x(i)},${y(d.runs)}`).join(' ');
  const ticks = [0, Math.ceil(max / 2), max];

  return <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img"
    aria-label="Weekly findings found, resolved and runs">
    <clipPath id={clip}><rect x="0" y="0" width={W} height={base}/></clipPath>
    {ticks.map(t => <g key={t}>
      <line x1={padX} x2={W - padX} y1={y(t)} y2={y(t)} stroke="var(--line-soft)"/>
      <text x={padX - 6} y={y(t) + 3} textAnchor="end" fontSize="9" fill="var(--muted)">{t}</text>
    </g>)}
    {data.map((d, i) => <g key={d.week}>
      <rect x={x(i) - barW - 1} y={y(d.found)} width={barW} height={base - y(d.found)} rx="1.5" fill="var(--breach)"/>
      <rect x={x(i) + 1} y={y(d.resolved)} width={barW} height={base - y(d.resolved)} rx="1.5" fill="var(--verified)"/>
      <text x={x(i)} y={base + 14} textAnchor="middle" fontSize="9" fill="var(--muted)">
        {d.week.slice(5).replace('-', '/')}</text>
    </g>)}
    <polyline points={line} fill="none" stroke="var(--accent)" strokeWidth="1.6"
      clipPath={`url(#${clip})`} opacity="0.9"/>
    {data.map((d, i) => <circle key={d.week} cx={x(i)} cy={y(d.runs)} r="2.4" fill="var(--accent)"/>)}
  </svg>;
}

export function TrendLegend() {
  return <div className="evo-legend" style={{marginTop: 10}}>
    <span><span className="evo-hit-key" style={{background: 'var(--breach)'}}/>Findings found</span>
    <span><span className="evo-hit-key" style={{background: 'var(--verified)'}}/>Resolved</span>
    <span><span className="evo-hit-key" style={{background: 'var(--accent)', borderRadius: '50%'}}/>Runs</span>
  </div>;
}
