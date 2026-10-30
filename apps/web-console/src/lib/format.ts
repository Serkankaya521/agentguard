import type {Verdict} from '@/lib/control';

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : '—';
}

export function score(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === '') return '—';
  const n = Number(value);
  return Number.isFinite(n) ? n.toFixed(2) : '—';
}

export function when(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  // Read the chosen language directly so call sites don't all need the t() function.
  let tr = false;
  try { tr = localStorage.getItem('agentguard.lang') === 'tr'; } catch { /* ignore */ }
  const minutes = Math.round((Date.now() - date.getTime()) / 60000);
  if (minutes >= 0 && minutes < 1) return tr ? 'az önce' : 'just now';
  if (minutes > 0 && minutes < 60) return tr ? `${minutes} dk önce` : `${minutes} min ago`;
  if (minutes > 0 && minutes < 60 * 24) return tr ? `${Math.round(minutes / 60)} sa önce` : `${Math.round(minutes / 60)} h ago`;
  return date.toLocaleString(tr ? 'tr-TR' : undefined, {dateStyle: 'medium', timeStyle: 'short'});
}

export function duration(start: string | null, end: string | null): string {
  if (!start || !end) return '—';
  const seconds = Math.max(0, Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000));
  return seconds < 90 ? `${seconds}s` : `${Math.round(seconds / 60)} min`;
}

type T = (key: string, vars?: Record<string, string | number>) => string;

export function every(minutes: number | null | undefined, t?: T): string {
  const tr = t && t('unit.dayShort') === 'g';
  if (!minutes) return tr ? 'zamanlanmamış' : 'not scheduled';
  if (minutes % 10080 === 0) return minutes === 10080 ? (tr ? 'haftalık' : 'weekly') : (tr ? `${minutes / 10080} haftada bir` : `every ${minutes / 10080} weeks`);
  if (minutes % 1440 === 0) return minutes === 1440 ? (tr ? 'günlük' : 'daily') : (tr ? `${minutes / 1440} günde bir` : `every ${minutes / 1440} days`);
  if (minutes % 60 === 0) return minutes === 60 ? (tr ? 'saatlik' : 'hourly') : (tr ? `${minutes / 60} saatte bir` : `every ${minutes / 60} h`);
  return tr ? `${minutes} dakikada bir` : `every ${minutes} min`;
}

export function origin(url: string | undefined): string {
  if (!url) return '—';
  try { return new URL(url).origin; } catch { return '—'; }
}

type Tone = 'breach' | 'verified' | 'signal' | 'accent' | '';

export function runTone(status: string): Tone {
  return ({completed: 'verified', running: 'accent', queued: '', failed: 'breach', stopped: 'signal'} as Record<string, Tone>)[status] ?? '';
}

export function findingTone(state: string): Tone {
  if (state === 'RESOLVED_VERIFIED') return 'verified';
  if (state === 'FALSE_POSITIVE') return '';
  if (state === 'FIX_PROPOSED' || state === 'RETESTING') return 'signal';
  return 'breach';
}

export function regressionTone(status: string | null | undefined): Tone {
  return status === 'passed' ? 'verified' : status === 'reopened' ? 'breach' : '';
}

// Remediation SLA by severity, in days. Industry-standard shape (critical fastest).
// A single place to tune; later this can come from a tenant policy.
const SLA_DAYS: Record<string, number> = {CRITICAL: 7, HIGH: 30, MEDIUM: 60, LOW: 90};
const DAY = 86_400_000;
const OPEN_STATES = new Set(['SUSPECTED', 'VALIDATING', 'CONFIRMED', 'FIX_PROPOSED', 'RETESTING', 'REOPENED']);

export type Sla = {
  tracked: boolean; open: boolean; dueDays: number | null; ageDays: number;
  remainingDays: number | null; breached: boolean; tone: Tone; label: string;
};

/** Age and remediation-SLA status for a finding. Closed findings report resolution time. */
export function sla(severity: string | undefined, state: string, createdAt: string,
                    updatedAt?: string, t?: T): Sla {
  const d = t ? t('unit.dayShort') : 'd';
  const tr = d === 'g';
  const created = new Date(createdAt).getTime();
  const open = OPEN_STATES.has(state);
  const until = open ? Date.now() : new Date(updatedAt || createdAt).getTime();
  const ageDays = Math.max(0, Math.floor((until - created) / DAY));
  const dueDays = SLA_DAYS[(severity || '').toUpperCase()] ?? null;
  if (!open) return {tracked: false, open, dueDays, ageDays, remainingDays: null, breached: false,
                     tone: 'verified', label: tr ? `${ageDays}${d} içinde kapandı` : `closed in ${ageDays}${d}`};
  if (dueDays === null) return {tracked: false, open, dueDays, ageDays, remainingDays: null, breached: false,
                                tone: '', label: tr ? `${ageDays}${d}` : `${ageDays}${d} old`};
  const remainingDays = dueDays - ageDays;
  const breached = remainingDays < 0;
  const tone: Tone = breached ? 'breach' : remainingDays <= Math.ceil(dueDays / 3) ? 'signal' : '';
  const label = breached ? (tr ? `SLA ${-remainingDays}${d} aşıldı` : `SLA breached ${-remainingDays}${d}`)
    : (tr ? `SLA'ya ${remainingDays}${d}` : `${remainingDays}${d} to SLA`);
  return {tracked: true, open, dueDays, ageDays, remainingDays, breached, tone, label};
}

const ACTION_KEY: Record<string, string> = {
  'finding.create': 'audit.create', 'finding.transition': 'audit.transition',
  'finding.write': 'audit.write', 'campaign.run.report.export': 'audit.export',
  'campaign.run.export.json': 'audit.export', 'campaign.run.export.csv': 'audit.export',
  'finding.feedback.good': 'audit.feedback', 'finding.feedback.bad': 'audit.feedback',
  'finding.feedback.clear': 'audit.feedback',
};
export function auditLabel(action: string, t: T): string {
  const key = ACTION_KEY[action];
  return key ? t(key) : action.replaceAll('.', ' ');
}

/** Human category label from the API category key, via i18n (cat.<key>). */
export function categoryLabel(key: string | null | undefined, t: T): string {
  if (!key) return '—';
  const label = t(`cat.${key}`);
  return label === `cat.${key}` ? key : label;
}

/** "LLM02 · Sensitive Information Disclosure" from an OWASP id, or the id alone. */
export function owaspLabel(owaspId: string | null | undefined, t: T): string {
  if (!owaspId) return '—';
  const title = t(`owasp.${owaspId}`);
  return title === `owasp.${owaspId}` ? owaspId : `${owaspId} · ${title}`;
}

// Verdict text lives in the i18n dictionary under verdict.<code>.{t,d}; only the
// color tone stays here since it is presentation, not copy.
export const VERDICT_TONE: Record<Verdict, 'breach' | 'verified' | 'signal'> = {
  CRITICAL: 'breach', HIGH: 'breach', MEDIUM: 'breach', LOW: 'breach',
  RESOLVED: 'verified', SIGNAL: 'signal', CLEAR: 'verified',
};
