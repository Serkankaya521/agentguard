"""Database trust boundary for the Control API."""
import hashlib
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from uuid import UUID

import psycopg
from fastapi import HTTPException
from psycopg_pool import PoolTimeout
from psycopg.rows import dict_row

from identity import Principal
from rbac import permits
from abac import attributes_allow

log = logging.getLogger("agentguard.control.database")
_current_request: ContextVar[object | None] = ContextVar("control_request", default=None)


@contextmanager
def bind_request(request):
    """Expose the active request to synchronous route handlers and dependencies."""
    token = _current_request.set(request)
    try:
        yield
    finally:
        _current_request.reset(token)


class Database:
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 16):
        if not 1 <= min_size <= max_size <= 64:
            raise ValueError("invalid connection pool bounds")
        self.dsn = dsn
        self.min_size, self.max_size = min_size, max_size
        self._pool = None
        self._pool_lock = Lock()

    def _get_pool(self):
        if self._pool is None:
            with self._pool_lock:
                if self._pool is None:
                    from psycopg_pool import ConnectionPool
                    self._pool = ConnectionPool(
                        self.dsn, min_size=self.min_size, max_size=self.max_size,
                        timeout=.25, open=False,
                        kwargs={"row_factory":dict_row,
                                "options":"-c statement_timeout=3000 -c lock_timeout=1000"},
                    )
                    self._pool.open(wait=False)
        return self._pool

    def close(self):
        if self._pool is not None:
            self._pool.close()

    @contextmanager
    def connect(self):
        with self._get_pool().connection(timeout=.25) as conn:
            role = conn.execute(
                "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user"
            ).fetchone()
            owner = conn.execute(
                "SELECT tableowner=current_user AS owned FROM pg_tables "
                "WHERE schemaname='platform' AND tablename='organizations'"
            ).fetchone()
            if not owner or owner["owned"] or role["rolsuper"] or role["rolbypassrls"]:
                raise HTTPException(503, "UNSAFE_DATABASE_ROLE")
            yield conn

    @contextmanager
    def authenticated(self, authorization: str | None):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "UNAUTHENTICATED")
        token = authorization[7:]
        if not 32 <= len(token) <= 256:
            raise HTTPException(401, "UNAUTHENTICATED")
        with self.connect() as conn:
            credential = conn.execute(
                "SELECT * FROM platform.authenticate_credential(%s)",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()
            if not credential:
                raise HTTPException(401, "UNAUTHENTICATED")
            conn.execute(
                "SELECT set_config('app.tenant_id',%s,true)",
                (str(credential["tenant_id"]),),
            )
            identity = conn.execute(
                "SELECT identity_type,status,attributes FROM platform.identities WHERE id=%s",
                (credential["identity_id"],),
            ).fetchone()
            if identity and identity["status"] != "active":
                raise HTTPException(401, "IDENTITY_INACTIVE")
            memberships = conn.execute(
                "SELECT workspace_id,role,attributes FROM platform.memberships "
                "WHERE identity_id=%s", (credential["identity_id"],),
            ).fetchall() if identity else []
            org_role = next((m["role"] for m in memberships if m["workspace_id"] is None), None)
            workspace_roles = {str(m["workspace_id"]): m["role"] for m in memberships if m["workspace_id"]}
            attributes = dict(identity["attributes"]) if identity else {}
            # Bootstrap credentials are operator-provisioned. Once an identity
            # exists, persisted memberships become its only role source.
            if not identity or (credential["label"] == "bootstrap" and not memberships):
                org_role = credential["role"]
            principal = Principal(
                tenant_id=str(credential["tenant_id"]),
                identity_id=str(credential["identity_id"]),
                identity_type=(identity["identity_type"] if identity else "service"),
                organization_role=org_role,
                workspace_roles=workspace_roles,
                attributes=attributes,
            )
            request = _current_request.get()
            if request is not None:
                request.state.auth_principal = principal
            yield conn, principal

    def audit_authorization_denial(self, principal: Principal, correlation_id: UUID):
        """Persist a denial independently of the rolled-back request transaction."""
        try:
            with self.connect() as conn:
                conn.execute("SELECT set_config('app.tenant_id',%s,true)",
                             (principal.tenant_id,))
                conn.execute(
                    "INSERT INTO platform.audit "
                    "(tenant_id,identity_id,correlation_id,action,resource_id) "
                    "VALUES(%s,%s,%s,'authorization.denied',%s)",
                    (principal.tenant_id, principal.identity_id,
                     correlation_id, correlation_id),
                )
        except (psycopg.Error, PoolTimeout):
            # The original denial must remain fail-closed even if observability is degraded.
            log.exception("authorization_denial_audit_failed correlation_id=%s",
                          correlation_id)

    @staticmethod
    def authorize(principal: Principal, permission: str,
                  workspace_id: str | None = None,
                  environment_kind: str | None = None,
                  attributes: dict | None = None):
        if not permits(principal, permission, workspace_id):
            raise HTTPException(403, "FORBIDDEN")
        if not attributes_allow(principal, environment_kind=environment_kind, required=attributes):
            raise HTTPException(403, "ABAC_DENIED")


def require_row(row):
    if not row:
        raise HTTPException(404, "NOT_FOUND")
    return row


def audit(conn, principal: Principal, correlation_id, action: str, resource_id):
    conn.execute(
        "INSERT INTO platform.audit "
        "(tenant_id,identity_id,correlation_id,action,resource_id) VALUES(%s,%s,%s,%s,%s)",
        (principal.tenant_id, principal.identity_id, correlation_id, action, resource_id),
    )


def enqueue_event(conn, principal: Principal, *, namespace: str, event_type: str,
                  payload: dict, priority: str = "P2"):
    sequence = conn.execute(
        "INSERT INTO platform.event_sequences(tenant_id,namespace,sequence) VALUES(%s,%s,0) "
        "ON CONFLICT(tenant_id,namespace) DO UPDATE SET sequence=platform.event_sequences.sequence+1 "
        "RETURNING sequence", (principal.tenant_id, namespace),
    ).fetchone()["sequence"]
    event_id = payload.get("event_id")
    conn.execute(
        "INSERT INTO platform.outbox(tenant_id,id,namespace,sequence,event_type,priority,payload) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s)",
        (principal.tenant_id, event_id, namespace, sequence, event_type, priority,
         psycopg.types.json.Jsonb(payload)),
    )
    return sequence
