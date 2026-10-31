"""Runtime egress-guard events: ingest from the gateway forwarder, read for the console.

The runtime gateway (Developer A) decides shadow/enforce off the hot path and emits a
would-block/applied event; this control-plane surface only persists and serves it. No
secret value is ever accepted or stored — only the match class and reason codes. The
console displays these; it never recomputes a runtime decision from them.
"""
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import Header, HTTPException, Query, Request

from database import Database, audit

MATCH_TYPES = ('known_secret', 'generic_marker', 'mixed', 'none')
MODES = ('shadow', 'enforce')
RECENT_LIMIT_MAX = 200
SETTING_MODES = ('off', 'shadow', 'enforce')
SETTING_ACTIONS = ('mask', 'stop')
GUARD = 'egress_secret'


def _match_type(matches) -> str:
    """Collapse the per-signal match classes into one summary class."""
    uniq = {str(m) for m in (matches or []) if m}
    uniq &= {'known_secret', 'generic_marker'}
    if not uniq:
        return 'none'
    if len(uniq) == 1:
        return next(iter(uniq))
    return 'mixed'


def install_runtime_guard_routes(app, database: Database):
    @app.post('/v1/runtime/guard-events', status_code=201)
    def ingest_guard_event(body: dict, request: Request, authorization: str | None = Header(None)):
        """Persist one egress-guard event from the runtime forwarder (async path)."""
        body = body or {}
        try:
            workspace_id = UUID(str(body['workspace_id']))
            environment_id = UUID(str(body['environment_id']))
        except (KeyError, ValueError):
            raise HTTPException(422, 'INVALID_INPUT')
        mode = body.get('mode')
        guard = str(body.get('guard') or 'egress_secret')
        if mode not in MODES or not isinstance(body.get('would_block'), bool) \
                or not isinstance(body.get('applied'), bool):
            raise HTTPException(422, 'INVALID_INPUT')
        reason_codes = [str(c) for c in (body.get('reason_codes') or [])][:32]
        match_type = _match_type(body.get('matches'))
        severity = str(body.get('severity') or 'CRITICAL')[:16]
        occurred_at = body.get('occurred_at')
        try:
            occurred = datetime.fromisoformat(str(occurred_at).replace('Z', '+00:00')) if occurred_at \
                else datetime.now(timezone.utc)
        except ValueError:
            occurred = datetime.now(timezone.utc)
        event_id = uuid4()
        with database.authenticated(authorization) as (conn, principal):
            env = conn.execute('SELECT kind,workspace_id FROM platform.environments WHERE id=%s',
                               (environment_id,)).fetchone()
            if not env or str(env['workspace_id']) != str(workspace_id):
                raise HTTPException(404, 'NOT_FOUND')
            database.authorize(principal, 'finding.manage', str(workspace_id), env['kind'])
            conn.execute(
                'INSERT INTO platform.runtime_guard_events'
                '(tenant_id,id,workspace_id,environment_id,guard,mode,would_block,applied,'
                'match_type,severity,reason_codes,trace_id,agent_id,session_id,occurred_at) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                (principal.tenant_id, event_id, workspace_id, environment_id, guard, mode,
                 body['would_block'], body['applied'], match_type, severity, reason_codes,
                 _clip(body.get('trace_id')), _clip(body.get('agent_id')), _clip(body.get('session_id')),
                 occurred))
            audit(conn, principal, request.state.correlation_id, 'runtime.guard.ingest', event_id)
        return {'id': str(event_id), 'would_block': body['would_block'], 'applied': body['applied']}

    @app.get('/v1/runtime/guard-events')
    def guard_events(request: Request, workspace_id: UUID,
                     limit: int = Query(50, ge=1, le=RECENT_LIMIT_MAX),
                     authorization: str | None = Header(None)):
        """Workspace summary of egress-guard activity plus the most recent events."""
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, 'tenant.read', str(workspace_id))
            summary = conn.execute(
                "SELECT count(*) AS total, "
                "count(*) FILTER (WHERE would_block) AS would_block, "
                "count(*) FILTER (WHERE applied) AS applied, "
                "count(*) FILTER (WHERE mode='shadow') AS shadow, "
                "count(*) FILTER (WHERE mode='enforce') AS enforce, "
                "count(*) FILTER (WHERE occurred_at >= clock_timestamp() - interval '7 days') AS last_7d, "
                "count(*) FILTER (WHERE occurred_at >= clock_timestamp() - interval '30 days') AS last_30d, "
                "max(occurred_at) AS last_event_at "
                'FROM platform.runtime_guard_events WHERE workspace_id=%s', (workspace_id,)).fetchone()
            by_match = conn.execute(
                'SELECT match_type, count(*) AS n FROM platform.runtime_guard_events '
                'WHERE workspace_id=%s GROUP BY match_type', (workspace_id,)).fetchall()
            events = conn.execute(
                'SELECT id,guard,mode,would_block,applied,match_type,severity,reason_codes,'
                'trace_id,agent_id,session_id,occurred_at '
                'FROM platform.runtime_guard_events WHERE workspace_id=%s '
                'ORDER BY occurred_at DESC, id DESC LIMIT %s', (workspace_id, limit)).fetchall()
        return {
            'summary': {
                'total': summary['total'], 'would_block': summary['would_block'],
                'applied': summary['applied'], 'shadow': summary['shadow'], 'enforce': summary['enforce'],
                'last_7d': summary['last_7d'], 'last_30d': summary['last_30d'],
                'last_event_at': summary['last_event_at'],
                'by_match': {row['match_type']: row['n'] for row in by_match},
            },
            'events': [dict(row) for row in events],
        }

    @app.get('/v1/runtime/guard-settings')
    def guard_settings(request: Request, workspace_id: UUID, authorization: str | None = Header(None)):
        """Per-environment guard mode for this workspace. Environments without a stored
        setting report the safe default (watch), marked as not yet configured."""
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, 'tenant.read', str(workspace_id))
            rows = conn.execute(
                "SELECT e.id AS environment_id, e.name AS environment_name, e.kind AS environment_kind, "
                "coalesce(s.guard,%s) AS guard, coalesce(s.mode,'shadow') AS mode, "
                "coalesce(s.action,'mask') AS action, coalesce(s.version,0) AS version, "
                "s.updated_at, (s.environment_id IS NOT NULL) AS configured "
                "FROM platform.environments e "
                "LEFT JOIN platform.runtime_guard_settings s "
                "  ON s.tenant_id=e.tenant_id AND s.environment_id=e.id AND s.guard=%s "
                "WHERE e.workspace_id=%s ORDER BY e.name", (GUARD, GUARD, workspace_id)).fetchall()
        return {'default_mode': 'shadow', 'settings': [dict(row) for row in rows]}

    @app.put('/v1/runtime/guard-settings/{environment_id}')
    def set_guard_setting(environment_id: UUID, body: dict, request: Request,
                          authorization: str | None = Header(None)):
        """Set the egress-guard mode/action for one environment (last write wins)."""
        body = body or {}
        mode, action = body.get('mode'), body.get('action', 'mask')
        if mode not in SETTING_MODES or action not in SETTING_ACTIONS:
            raise HTTPException(422, 'INVALID_INPUT')
        with database.authenticated(authorization) as (conn, principal):
            env = conn.execute('SELECT kind,workspace_id FROM platform.environments WHERE id=%s',
                               (environment_id,)).fetchone()
            if not env:
                raise HTTPException(404, 'NOT_FOUND')
            database.authorize(principal, 'finding.manage', str(env['workspace_id']), env['kind'])
            row = conn.execute(
                'INSERT INTO platform.runtime_guard_settings'
                '(tenant_id,workspace_id,environment_id,guard,mode,action,updated_by) '
                'VALUES(%s,%s,%s,%s,%s,%s,%s) '
                'ON CONFLICT (tenant_id,environment_id,guard) DO UPDATE SET '
                'mode=excluded.mode, action=excluded.action, '
                'version=platform.runtime_guard_settings.version+1, '
                'updated_by=excluded.updated_by, updated_at=clock_timestamp() RETURNING *',
                (principal.tenant_id, env['workspace_id'], environment_id, GUARD, mode, action,
                 principal.identity_id)).fetchone()
            audit(conn, principal, request.state.correlation_id, 'runtime.guard.settings.update', environment_id)
            return dict(row)


def _clip(value, length: int = 128):
    return str(value)[:length] if value else None
