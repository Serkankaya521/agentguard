"""Assessment read models for the operations console and the customer report.

Everything here is read-only, tenant-scoped through the authenticated
connection (FORCE RLS) and bounded. Raw target responses are never stored, so
they are never returned; candidate payloads are the tenant's own attack inputs.
"""
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import Header, HTTPException, Query, Request
from fastapi.responses import Response

from assessment_report import build_assessment_pdf, summarize
from campaigns import public
from database import Database, audit

MAX_RUN_CANDIDATES = 2000
PAYLOAD_PREVIEW = 400


def load_run_bundle(conn, campaign_id: UUID, run_id: UUID) -> dict:
    campaign = conn.execute('SELECT * FROM platform.campaigns WHERE id=%s', (campaign_id,)).fetchone()
    if not campaign:
        raise HTTPException(404, 'NOT_FOUND')
    run = conn.execute('SELECT * FROM platform.campaign_runs WHERE id=%s AND campaign_id=%s',
                       (run_id, campaign_id)).fetchone()
    if not run:
        raise HTTPException(404, 'NOT_FOUND')
    environment = conn.execute('SELECT id,name,kind FROM platform.environments WHERE id=%s',
                               (campaign['environment_id'],)).fetchone()
    candidates = conn.execute(
        'SELECT id,generation,lineage,payload,response_hash,fitness,evidence_level,finding_id,created_at '
        'FROM platform.campaign_candidates WHERE run_id=%s ORDER BY generation,created_at,id LIMIT %s',
        (run_id, MAX_RUN_CANDIDATES)).fetchall()
    finding_ids = sorted({row['finding_id'] for row in candidates if row['finding_id']}, key=str)
    findings = []
    if finding_ids:
        findings = conn.execute(
            'SELECT f.id,f.state,f.version,f.document,f.created_at,f.updated_at,'
            'r.id AS regression_case_id,r.status AS regression_status,r.last_run_at AS regression_last_run_at '
            'FROM platform.findings f LEFT JOIN platform.regression_cases r '
            'ON r.tenant_id=f.tenant_id AND r.finding_id=f.id WHERE f.id = ANY(%s) ORDER BY f.created_at,f.id',
            (finding_ids,)).fetchall()
    evidence = None
    if run['evidence_object_id']:
        evidence = conn.execute(
            'SELECT id,object_key,media_type,size_bytes,object_hash,record_hash,created_at '
            'FROM platform.evidence_objects WHERE id=%s', (run['evidence_object_id'],)).fetchone()
    return {
        'campaign': public(campaign),
        'environment': dict(environment) if environment else None,
        'run': dict(run),
        'candidates': [dict(row, fitness=float(row['fitness'])) for row in candidates],
        'findings': [{
            'id': row['id'], 'state': row['state'], 'version': row['version'], 'document': row['document'],
            'created_at': row['created_at'], 'updated_at': row['updated_at'],
            'regression': {'case_id': row['regression_case_id'], 'status': row['regression_status'],
                           'last_run_at': row['regression_last_run_at']} if row['regression_case_id'] else None,
        } for row in findings],
        'evidence': dict(evidence) if evidence else None,
    }


def console_view(bundle: dict) -> dict:
    """Bundle + summary, with payloads shortened for list display."""
    view = dict(bundle)
    view['summary'] = summarize(bundle)
    view['candidates'] = [
        dict(row, payload=row['payload'][:PAYLOAD_PREVIEW],
             payload_truncated=len(row['payload']) > PAYLOAD_PREVIEW)
        for row in bundle['candidates']
    ]
    view['candidates_truncated'] = len(bundle['candidates']) >= MAX_RUN_CANDIDATES
    return view


def load_finding_detail(conn, finding_id: UUID) -> dict:
    finding = conn.execute(
        'SELECT id,workspace_id,environment_id,state,version,document,created_at,updated_at '
        'FROM platform.findings WHERE id=%s', (finding_id,)).fetchone()
    if not finding:
        raise HTTPException(404, 'NOT_FOUND')
    # State history comes from the tamper-evident audit chain (tenant-scoped by RLS).
    timeline = conn.execute(
        'SELECT action,identity_id,correlation_id,occurred_at,record_hash '
        'FROM platform.audit WHERE resource_id=%s ORDER BY id', (finding_id,)).fetchall()
    regression = conn.execute(
        'SELECT id AS case_id,status,expected_block,last_run_at,created_at '
        'FROM platform.regression_cases WHERE finding_id=%s', (finding_id,)).fetchone()
    # The confirming attack: the candidate that produced this finding is the reproduction.
    candidate = conn.execute(
        'SELECT c.run_id,c.generation,c.lineage,c.payload,c.response_hash,c.fitness,c.evidence_level,'
        'r.campaign_id FROM platform.campaign_candidates c '
        'JOIN platform.campaign_runs r ON r.tenant_id=c.tenant_id AND r.id=c.run_id '
        'WHERE c.finding_id=%s ORDER BY c.created_at LIMIT 1', (finding_id,)).fetchone()
    return {
        'finding': dict(finding),
        'timeline': [dict(row) for row in timeline],
        'regression': dict(regression) if regression else None,
        'origin': {
            'run_id': candidate['run_id'], 'campaign_id': candidate['campaign_id'],
            'candidate': {'generation': candidate['generation'], 'lineage': candidate['lineage'],
                          'payload': candidate['payload'], 'response_hash': candidate['response_hash'],
                          'fitness': float(candidate['fitness']), 'evidence_level': candidate['evidence_level']},
        } if candidate else None,
    }


def install_assessment_routes(app, database: Database):
    @app.get('/v1/findings/{finding_id}/detail')
    def finding_detail(finding_id: UUID, request: Request, authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            detail = load_finding_detail(conn, finding_id)
            database.authorize(principal, 'tenant.read', str(detail['finding']['workspace_id']))
            return detail

    @app.get('/v1/campaigns/{campaign_id}/runs/{run_id}')
    def run_detail(campaign_id: UUID, run_id: UUID, request: Request,
                   authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            bundle = load_run_bundle(conn, campaign_id, run_id)
            database.authorize(principal, 'tenant.read', str(bundle['campaign']['workspace_id']))
            return console_view(bundle)

    @app.get('/v1/campaigns/{campaign_id}/runs/{run_id}/report.pdf')
    def run_report(campaign_id: UUID, run_id: UUID, request: Request,
                   lang: Literal['tr', 'en'] = Query('tr'),
                   authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            bundle = load_run_bundle(conn, campaign_id, run_id)
            database.authorize(principal, 'report.read', str(bundle['campaign']['workspace_id']))
            audit(conn, principal, request.state.correlation_id, 'campaign.run.report.export', run_id)
        content = build_assessment_pdf(bundle, lang=lang, generated_at=datetime.now(timezone.utc))
        filename = f'agentguard-assessment-{str(run_id)[:8]}-{lang}.pdf'
        return Response(content, media_type='application/pdf', headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
        })

    @app.get('/v1/assessments/overview')
    def overview(request: Request, workspace_id: UUID, authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, 'tenant.read', str(workspace_id))
            campaigns = conn.execute(
                "SELECT count(*) AS total, count(*) FILTER (WHERE status='active') AS active "
                'FROM platform.campaigns WHERE workspace_id=%s', (workspace_id,)).fetchone()
            runs = conn.execute(
                "SELECT count(*) AS total, count(*) FILTER (WHERE r.status='completed') AS completed, "
                "count(*) FILTER (WHERE r.status IN ('failed','stopped')) AS failed, "
                'coalesce(sum(r.candidates_evaluated),0) AS requests, max(r.completed_at) AS last_completed_at '
                'FROM platform.campaign_runs r JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id '
                "WHERE c.workspace_id=%s AND r.created_at >= clock_timestamp() - interval '30 days'",
                (workspace_id,)).fetchone()
            findings = conn.execute(
                "SELECT state, coalesce(document->>'severity','UNKNOWN') AS severity, count(*) AS n "
                'FROM platform.findings WHERE workspace_id=%s GROUP BY 1,2', (workspace_id,)).fetchall()
            regressions = conn.execute(
                'SELECT r.status, count(*) AS n FROM platform.regression_cases r '
                'JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id '
                'WHERE c.workspace_id=%s GROUP BY 1', (workspace_id,)).fetchall()
            recent = conn.execute(
                'SELECT r.id,r.campaign_id,c.name AS campaign_name,r.status,r.candidates_evaluated,'
                'r.findings_created,r.best_score,r.created_at,r.completed_at '
                'FROM platform.campaign_runs r JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id '
                'WHERE c.workspace_id=%s ORDER BY r.created_at DESC LIMIT 8', (workspace_id,)).fetchall()
            # Remediation performance: resolution time vs severity SLA (critical 7d … low 90d).
            remediation = conn.execute(
                "SELECT count(*) AS resolved, "
                "coalesce(avg(extract(epoch FROM (updated_at-created_at))/86400),0) AS mttr_days, "
                "count(*) FILTER (WHERE extract(epoch FROM (updated_at-created_at))/86400 <= "
                "  CASE upper(coalesce(document->>'severity','')) "
                "    WHEN 'CRITICAL' THEN 7 WHEN 'HIGH' THEN 30 WHEN 'MEDIUM' THEN 60 WHEN 'LOW' THEN 90 ELSE 1e9 END) AS within_sla "
                "FROM platform.findings WHERE workspace_id=%s AND state='RESOLVED_VERIFIED'",
                (workspace_id,)).fetchone()
            # 8-week activity trend, each series bucketed by ISO week.
            trend_runs = conn.execute(
                "SELECT to_char(date_trunc('week',r.created_at),'YYYY-MM-DD') AS week, count(*) AS n, "
                "coalesce(sum(r.findings_created),0) AS found "
                'FROM platform.campaign_runs r JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id '
                "WHERE c.workspace_id=%s AND r.created_at >= date_trunc('week',clock_timestamp()) - interval '7 weeks' "
                'GROUP BY 1', (workspace_id,)).fetchall()
            trend_resolved = conn.execute(
                "SELECT to_char(date_trunc('week',updated_at),'YYYY-MM-DD') AS week, count(*) AS n "
                "FROM platform.findings WHERE workspace_id=%s AND state='RESOLVED_VERIFIED' "
                "AND updated_at >= date_trunc('week',clock_timestamp()) - interval '7 weeks' GROUP BY 1",
                (workspace_id,)).fetchall()
        open_by_severity: dict[str, int] = {}
        by_state: dict[str, int] = {}
        for row in findings:
            by_state[row['state']] = by_state.get(row['state'], 0) + row['n']
            if row['state'] not in ('RESOLVED_VERIFIED', 'FALSE_POSITIVE'):
                open_by_severity[row['severity']] = open_by_severity.get(row['severity'], 0) + row['n']
        # Build 8 contiguous weekly buckets so the UI never has to guess gaps.
        from datetime import date, timedelta
        monday = date.today() - timedelta(days=date.today().weekday())
        weeks = [(monday - timedelta(weeks=offset)).isoformat() for offset in range(7, -1, -1)]
        runs_by_week = {row['week']: row for row in trend_runs}
        resolved_by_week = {row['week']: row['n'] for row in trend_resolved}
        trend = [{'week': week, 'runs': runs_by_week.get(week, {}).get('n', 0),
                  'found': runs_by_week.get(week, {}).get('found', 0),
                  'resolved': resolved_by_week.get(week, 0)} for week in weeks]

        open_total = sum(open_by_severity.values())
        resolved_total = int(remediation['resolved'])
        within = int(remediation['within_sla'])
        sla_rate = round(within / resolved_total, 3) if resolved_total else None
        # Posture score (0–100): starts at 100, penalised by open findings weighted by
        # severity, softened by SLA compliance. Deterministic, explainable, bounded.
        weights = {'CRITICAL': 25, 'HIGH': 12, 'MEDIUM': 5, 'LOW': 2}
        penalty = sum(weights.get(sev.upper(), 4) * n for sev, n in open_by_severity.items())
        posture = max(0, min(100, 100 - penalty))
        return {
            'campaigns': dict(campaigns),
            'runs_30d': dict(runs),
            'findings_by_state': by_state,
            'open_findings_by_severity': open_by_severity,
            'regressions': {row['status']: row['n'] for row in regressions},
            'recent_runs': recent,
            'posture': {
                'score': posture, 'open_findings': open_total,
                'mttr_days': round(float(remediation['mttr_days']), 1) if resolved_total else None,
                'resolved_total': resolved_total, 'sla_compliance': sla_rate,
                'sla_within': within, 'sla_breached': resolved_total - within,
            },
            'trend': trend,
        }
