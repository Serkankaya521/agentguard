'use client';
import {useMemo, useState} from 'react';
import {Candidate} from '@/lib/control';
import {useT} from '@/lib/i18n';
import {score} from '@/lib/format';

const VERIFIED = new Set(['target_canary', 'tool_observation']);

/** Fitness 0..1 on a pale-to-cobalt ramp; verified leaks are drawn separately in red. */
function fill(fitness: number): string {
  const stops = [[232, 236, 241], [159, 177, 242], [36, 71, 214]];
  const t = Math.min(1, Math.max(0, fitness)) * 2;
  const [a, b] = t <= 1 ? [stops[0], stops[1]] : [stops[1], stops[2]];
  const f = t <= 1 ? t : t - 1;
  return `rgb(${a.map((v, i) => Math.round(v + (b[i] - v) * f)).join(',')})`;
}

export function EvolutionGrid({candidates}: {candidates: Candidate[]}) {
  const {t} = useT();
  const generations = useMemo(() => {
    const map = new Map<number, Candidate[]>();
    for (const candidate of candidates) map.set(candidate.generation, [...(map.get(candidate.generation) || []), candidate]);
    return [...map.entries()].sort((a, b) => a[0] - b[0]);
  }, [candidates]);
  const firstHit = candidates.find(c => VERIFIED.has(c.evidence_level));
  const [selected, setSelected] = useState<Candidate | undefined>(firstHit);

  if (!candidates.length) return <p className="muted">{t('evo.noCandidates')}</p>;
  return <div>
    <div className="evolution" role="group" aria-label="Attack candidates by generation">
      {generations.map(([generation, rows]) => {
        const best = Math.max(...rows.map(r => r.fitness));
        return <div className="evo-row" key={generation}>
          <span>{t('evo.generation')} {generation}</span>
          <div className="evo-cells">{rows.map(candidate => {
            const hit = VERIFIED.has(candidate.evidence_level);
            return <button key={candidate.id} type="button" className={`evo-cell${hit ? ' hit' : ''}`}
              style={{background: fill(candidate.fitness)}} aria-pressed={selected?.id === candidate.id}
              aria-label={`${t('evo.generation')} ${generation}, ${score(candidate.fitness)}`}
              title={`${score(candidate.fitness)}${hit ? ' · ' + t('evo.verified') : ''}`}
              onClick={() => setSelected(candidate)}/>;
          })}</div>
          <span>{score(best)}</span>
        </div>;
      })}
    </div>
    <div className="evo-legend">
      <span>{t('evo.heuristic')}</span><span>0</span><span className="evo-scale" aria-hidden="true"/><span>1</span>
      <span><span className="evo-hit-key" aria-hidden="true"/>{t('evo.leaked')}</span>
    </div>
    {selected && <div className="candidate-detail">
      <dl className="facts">
        <dt>{t('evo.generation')}</dt><dd>{selected.generation}</dd>
        <dt>{t('evo.mutations')}</dt><dd>{selected.lineage.length ? selected.lineage.join(' → ') : t('evo.seed')}</dd>
        <dt>{t('evo.score')}</dt><dd>{score(selected.fitness)}</dd>
        <dt>{t('evo.evidence')}</dt><dd>{VERIFIED.has(selected.evidence_level)
          ? <strong style={{color: 'var(--breach)'}}>{t('evo.verified')}</strong> : t('evo.heuristicOnly')}</dd>
        <dt>{t('evo.responseDigest')}</dt><dd className="hash">{selected.response_hash}</dd>
      </dl>
      <pre>{selected.payload}{selected.payload_truncated ? ' …' : ''}</pre>
    </div>}
  </div>;
}
