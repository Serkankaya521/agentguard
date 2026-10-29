'use client';

export class ControlError extends Error {
  constructor(public code: string, public status: number) { super(code); }
}

export async function control<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(controlUrl(path), {
    ...init, headers: {'Content-Type': 'application/json', ...(init.headers || {})}, cache: 'no-store'});
  if (response.status === 401) {
    if (!location.pathname.startsWith('/login')) location.assign('/login');
    throw new ControlError('UNAUTHENTICATED', 401);
  }
  const body = await response.json().catch(() => ({code: 'INVALID_RESPONSE'}));
  if (!response.ok) throw new ControlError(body.code || `HTTP_${response.status}`, response.status);
  return body as T;
}

/** Same-origin proxy URL; used for downloads that the browser should handle itself. */
export function controlUrl(path: string): string {
  return '/api/control/' + path.replace(/^\//, '');
}

const MESSAGES: Record<string, string> = {
  FORBIDDEN: 'Your role does not allow this action in this workspace.',
  ABAC_DENIED: 'Your access is limited to other environment types.',
  NOT_FOUND: 'This item does not exist or belongs to another workspace.',
  VERSION_CONFLICT: 'Someone changed this item. Reload and try again.',
  SECRET_NOT_ASSIGNED: 'That secret reference is not assigned to your organization. Ask an admin to allow it.',
  TARGET_NOT_ASSIGNED: 'That target is not on your organization\'s authorized target list.',
  TENANT_QUOTA_EXCEEDED: 'Your organization reached its campaign or report limit.',
  SCHEDULE_REQUIRED: 'Set an interval and a first run time before activating the schedule.',
  INVALID_FINDING_TRANSITION: 'That state change is not allowed from the finding\'s current state.',
  CONTROL_API_UNAVAILABLE: 'The control API is not reachable. Check CONTROL_API_URL.',
  INVALID_INPUT: 'Some fields are invalid. Check the values and try again.',
  DATABASE_UNAVAILABLE: 'The control API database is unavailable. Try again shortly.',
};

export function explain(error: unknown): string {
  const code = error instanceof Error ? error.message : 'REQUEST_FAILED';
  return MESSAGES[code] || `Request failed (${code}).`;
}

export function idempotencyKey(scope: string): string {
  return `console-${scope}-${crypto.randomUUID()}`;
}

export type Row = Record<string, unknown>;

export type Workspace = {id: string; name: string};
export type Environment = {id: string; name: string; kind: string; workspace_id: string};

export type Campaign = {
  id: string; workspace_id: string; environment_id: string; name: string; status: 'active' | 'paused' | 'archived';
  target_type: string; target_config: {api_base?: string; model?: string};
  seed_prompt: string; objective_markers: string[]; request_budget: number; mutation_budget: number;
  interval_minutes: number | null; next_run_at: string | null; version: number;
  secret_configured: boolean; canary_configured: boolean; created_at: string; updated_at: string;
};

export type Run = {
  id: string; campaign_id: string; status: 'queued' | 'running' | 'completed' | 'failed' | 'stopped';
  scheduled_for: string; started_at: string | null; completed_at: string | null;
  candidates_evaluated: number; findings_created: number; best_score: number | string | null;
  evidence_object_id: string | null; error_code: string | null; created_at: string;
};

export type Candidate = {
  id: string; generation: number; lineage: string[]; payload: string; payload_truncated: boolean;
  response_hash: string; fitness: number; evidence_level: 'heuristic' | 'target_canary' | 'tool_observation';
  finding_id: string | null;
};

export type FindingDocument = {
  title?: string; severity?: string; root_cause?: string; remediation?: string; successful_mutations?: string[];
  evidence_pattern?: string; regression_fingerprint?: string; campaign_id?: string; run_id?: string;
};

export type Finding = {
  id: string; state: string; version: number; workspace_id?: string; environment_id?: string;
  document: FindingDocument; created_at: string; updated_at?: string;
  regression?: {case_id: string; status: string; last_run_at: string | null} | null;
};

export type Verdict = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'RESOLVED' | 'SIGNAL' | 'CLEAR';

export type RunSummary = {
  verdict: Verdict; requests: number; verified_findings: number; open_findings: number; best_score: number;
  strong_signals: number; generation_count: number; run_complete: boolean;
  generations: {generation: number; candidates: number; best: number; average: number; confirmed: number}[];
};

export type RunView = {
  campaign: Campaign; environment: Environment | null; run: Run; candidates: Candidate[];
  candidates_truncated: boolean; findings: Finding[]; summary: RunSummary;
  evidence: {id: string; object_key: string; object_hash: string; record_hash: string; size_bytes: number;
             created_at: string} | null;
};

export type TimelineEntry = {action: string; identity_id: string; correlation_id: string;
                             occurred_at: string; record_hash: string | null};

export type FindingDetail = {
  finding: Finding & {workspace_id: string; environment_id: string};
  timeline: TimelineEntry[];
  regression: {case_id: string; status: string; expected_block: boolean; last_run_at: string | null;
               created_at: string} | null;
  origin: {run_id: string; campaign_id: string;
           candidate: {generation: number; lineage: string[]; payload: string; response_hash: string;
                       fitness: number; evidence_level: string}} | null;
};

export type Overview = {
  campaigns: {total: number; active: number};
  runs_30d: {total: number; completed: number; failed: number; requests: number; last_completed_at: string | null};
  findings_by_state: Record<string, number>;
  open_findings_by_severity: Record<string, number>;
  regressions: Record<string, number>;
  recent_runs: (Run & {campaign_name: string})[];
  posture: {score: number; open_findings: number; mttr_days: number | null; resolved_total: number;
            sla_compliance: number | null; sla_within: number; sla_breached: number};
  trend: {week: string; runs: number; found: number; resolved: number}[];
};
