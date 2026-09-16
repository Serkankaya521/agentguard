"""Developer B P0 platform routes.

All writes are tenant-scoped, authorized, audited and committed atomically with
their outbox events where an asynchronous consumer must observe the change.
"""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import secrets
from typing import Literal
from uuid import UUID, uuid4

import psycopg
from fastapi import Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from artifacts import load_verified
from compiler import compile_policy
from execution_gate import mint_approval_token
import integrity as evidence_integrity
from validation import validate

from database import Database, audit, enqueue_event, require_row


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IdentityInput(StrictModel):
    identity_type: Literal["user", "service"]
    external_subject: str | None = Field(default=None, max_length=255)
    display_name: str = Field(min_length=1, max_length=120)
    attributes: dict[str, object] = Field(default_factory=dict)
    status: Literal["active", "suspended", "deleted"] = "active"


class MembershipInput(StrictModel):
    identity_id: UUID
    workspace_id: UUID | None = None
    role: Literal["owner", "admin", "editor", "approver", "reader"]
    attributes: dict[str, object] = Field(default_factory=dict)


class CredentialInput(StrictModel):
    label: str = Field(min_length=1, max_length=120)
    expires_at: datetime


class AssetInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    asset_type: Literal["agent", "model", "mcp_server", "tool"]
    name: str = Field(min_length=1, max_length=120)
    metadata: dict[str, object] = Field(default_factory=dict)


class CapabilityInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    tool_asset_id: UUID
    document: dict


class ApprovalInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    tool_id: str = Field(min_length=1, max_length=255)
    capability_id: str = Field(min_length=1, max_length=255)
    resource: str = Field(min_length=1, max_length=2048)
    agent_id: str | None = Field(default=None, max_length=255)
    session_id: str | None = Field(default=None, max_length=255)
    expires_at: datetime
    use_mode: Literal["one_time", "reusable_scoped"] = "one_time"
    max_uses: int = Field(default=1, ge=1, le=1000)
    required_approvals: int = Field(default=1, ge=1, le=10)


class DecisionInput(StrictModel):
    decision: Literal["APPROVE", "DENY", "REVOKE"]
    reason: str | None = Field(default=None, max_length=1000)


class FindingInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    state: Literal["SUSPECTED", "VALIDATING", "CONFIRMED", "FIX_PROPOSED", "RETESTING", "RESOLVED_VERIFIED", "REOPENED", "FALSE_POSITIVE"] = "SUSPECTED"
    root_cause: str = Field(max_length=8000)
    details: dict[str, object] = Field(default_factory=dict)


class FindingTransition(StrictModel):
    state: Literal["SUSPECTED", "VALIDATING", "CONFIRMED", "FIX_PROPOSED", "RETESTING", "RESOLVED_VERIFIED", "REOPENED", "FALSE_POSITIVE"]


class PolicyInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    source: dict


class EvidenceInput(StrictModel):
    workspace_id: UUID
    environment_id: UUID
    event_id: str = Field(min_length=1, max_length=255)
    action_state: Literal["proposed", "blocked", "approved", "executed"]
    object_key: str = Field(min_length=1, max_length=900)
    media_type: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0, le=104857600)
    object_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sources: list[dict] = Field(min_length=1, max_length=50)
    trace_id: str | None = Field(default=None, max_length=255)


class UploadInput(StrictModel):
    object_key: str = Field(min_length=1, max_length=900)
    media_type: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


TRANSITIONS = {
    "SUSPECTED": {"VALIDATING", "FALSE_POSITIVE"},
    "VALIDATING": {"CONFIRMED", "FALSE_POSITIVE"},
    "CONFIRMED": {"FIX_PROPOSED", "FALSE_POSITIVE"},
    "FIX_PROPOSED": {"RETESTING"},
    "RETESTING": {"RESOLVED_VERIFIED", "REOPENED"},
    "RESOLVED_VERIFIED": {"REOPENED"},
    "REOPENED": {"FIX_PROPOSED", "RETESTING"},
    "FALSE_POSITIVE": {"REOPENED"},
}


def install_enterprise_routes(app, database: Database, *, policy_signing_key: str | None,
                              approval_signing_key: str | None, object_store=None,
                              evidence_signing_key: str | None = None):
    def environment(conn, environment_id):
        return require_row(conn.execute(
            "SELECT e.*,w.id AS authorized_workspace_id FROM platform.environments e "
            "JOIN platform.workspaces w ON w.tenant_id=e.tenant_id AND w.id=e.workspace_id "
            "WHERE e.id=%s", (environment_id,),
        ).fetchone())

    def page(conn, table, after, limit):
        return conn.execute(
            f"SELECT * FROM platform.{table} WHERE (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
            (after, after, limit),
        ).fetchall()

    @app.get("/v1/identities")
    def identities(request: Request, authorization: str | None = Header(None),
                   after: UUID | None = None, limit: int = Query(50, ge=1, le=100)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "tenant.read")
            return page(conn, "identities", after, limit)

    @app.put("/v1/identities/{identity_id}")
    def put_identity(identity_id: UUID, body: IdentityInput, request: Request,
                     authorization: str | None = Header(None), if_match: int = Header(0, ge=0)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "identity.manage")
            existing = conn.execute("SELECT * FROM platform.identities WHERE id=%s FOR UPDATE", (identity_id,)).fetchone()
            values = (body.identity_type, body.external_subject, body.display_name,
                      psycopg.types.json.Jsonb(body.attributes),body.status)
            if if_match == 0:
                if existing:
                    raise HTTPException(409, "VERSION_CONFLICT")
                row = conn.execute(
                    "INSERT INTO platform.identities(tenant_id,id,identity_type,external_subject,display_name,attributes,status) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                    (principal.tenant_id, identity_id, *values),
                ).fetchone()
            else:
                if existing and (existing["identity_type"] != body.identity_type or
                                 existing["external_subject"] != body.external_subject):
                    raise HTTPException(409,"IDENTITY_BINDING_IMMUTABLE")
                row = conn.execute(
                    "UPDATE platform.identities SET identity_type=%s,external_subject=%s,display_name=%s,attributes=%s,status=%s,version=version+1 "
                    "WHERE id=%s AND version=%s RETURNING *", (*values, identity_id, if_match),
                ).fetchone()
                if not row:
                    raise HTTPException(409 if existing else 404, "VERSION_CONFLICT" if existing else "NOT_FOUND")
            audit(conn, principal, request.state.correlation_id, "identity.write", identity_id)
            return row

    @app.get("/v1/memberships")
    def memberships(request: Request, workspace_id: UUID | None = None,
                    authorization: str | None = Header(None), after: UUID | None = None,
                    limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"tenant.read",str(workspace_id) if workspace_id else None)
            return conn.execute("SELECT * FROM platform.memberships WHERE workspace_id IS NOT DISTINCT FROM %s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.put("/v1/memberships/{membership_id}")
    def put_membership(membership_id: UUID, body: MembershipInput, request: Request,
                       authorization: str | None = Header(None), if_match: int = Header(0, ge=0)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "identity.manage", str(body.workspace_id) if body.workspace_id else None)
            require_row(conn.execute("SELECT id FROM platform.identities WHERE id=%s", (body.identity_id,)).fetchone())
            if body.workspace_id:
                require_row(conn.execute("SELECT id FROM platform.workspaces WHERE id=%s", (body.workspace_id,)).fetchone())
            existing = conn.execute("SELECT * FROM platform.memberships WHERE id=%s FOR UPDATE", (membership_id,)).fetchone()
            values = (body.identity_id, body.workspace_id, body.role, psycopg.types.json.Jsonb(body.attributes))
            if if_match == 0:
                if existing:
                    raise HTTPException(409, "VERSION_CONFLICT")
                row = conn.execute(
                    "INSERT INTO platform.memberships(tenant_id,id,identity_id,workspace_id,role,attributes) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *",
                    (principal.tenant_id, membership_id, *values),
                ).fetchone()
            else:
                if existing and (existing["identity_id"] != body.identity_id or
                                 existing["workspace_id"] != body.workspace_id):
                    raise HTTPException(409,"MEMBERSHIP_SCOPE_IMMUTABLE")
                row = conn.execute(
                    "UPDATE platform.memberships SET identity_id=%s,workspace_id=%s,role=%s,attributes=%s,version=version+1 WHERE id=%s AND version=%s RETURNING *",
                    (*values, membership_id, if_match),
                ).fetchone()
                if not row:
                    raise HTTPException(409 if existing else 404, "VERSION_CONFLICT" if existing else "NOT_FOUND")
            audit(conn, principal, request.state.correlation_id, "membership.write", membership_id)
            return row

    @app.delete("/v1/memberships/{membership_id}")
    def delete_membership(membership_id: UUID, request: Request, if_match: int = Header(ge=1),
                          authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            row = require_row(conn.execute("SELECT * FROM platform.memberships WHERE id=%s",(membership_id,)).fetchone())
            database.authorize(principal,"identity.manage",str(row["workspace_id"]) if row["workspace_id"] else None)
            deleted = conn.execute("DELETE FROM platform.memberships WHERE id=%s AND version=%s RETURNING id",(membership_id,if_match)).fetchone()
            if not deleted: raise HTTPException(409,"VERSION_CONFLICT")
            audit(conn,principal,request.state.correlation_id,"membership.delete",membership_id)
            return {"deleted":True}

    @app.post("/v1/identities/{identity_id}/credentials", status_code=201)
    def create_credential(identity_id: UUID, body: CredentialInput, request: Request, response: Response,
                          authorization: str | None = Header(None)):
        if body.expires_at <= datetime.now(timezone.utc) or body.expires_at > datetime.now(timezone.utc)+timedelta(days=366):
            raise HTTPException(422, "INVALID_EXPIRY")
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "identity.manage")
            require_row(conn.execute("SELECT id FROM platform.identities WHERE id=%s AND status='active'", (identity_id,)).fetchone())
            token = secrets.token_urlsafe(48)
            digest = __import__('hashlib').sha256(token.encode()).hexdigest()
            row = conn.execute(
                "INSERT INTO platform.credentials(token_hash,tenant_id,identity_id,role,expires_at,label) "
                "VALUES(%s,%s,%s,'reader',%s,%s) RETURNING credential_id,label,expires_at",
                (digest, principal.tenant_id, identity_id, body.expires_at, body.label),
            ).fetchone()
            audit(conn, principal, request.state.correlation_id, "credential.create", row["credential_id"])
            response.headers["Cache-Control"] = "no-store"
            return {**row, "token": token}

    @app.delete("/v1/credentials/{credential_id}")
    def revoke_credential(credential_id: UUID, request: Request,
                          authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "identity.manage")
            row = conn.execute(
                "UPDATE platform.credentials SET revoked=true WHERE tenant_id=%s AND credential_id=%s AND NOT revoked RETURNING credential_id",
                (principal.tenant_id, credential_id),
            ).fetchone()
            require_row(row)
            audit(conn, principal, request.state.correlation_id, "credential.revoke", credential_id)
            return {"revoked": True}

    @app.put("/v1/assets/{asset_id}")
    def put_asset(asset_id: UUID, body: AssetInput, request: Request,
                  authorization: str | None = Header(None), if_match: int = Header(0, ge=0)):
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            database.authorize(principal, "asset.manage", str(body.workspace_id), env["kind"])
            existing = conn.execute("SELECT * FROM platform.assets WHERE id=%s FOR UPDATE", (asset_id,)).fetchone()
            values = (body.workspace_id, body.environment_id, body.asset_type, body.name,
                      psycopg.types.json.Jsonb(body.metadata))
            if if_match == 0:
                if existing:
                    raise HTTPException(409, "VERSION_CONFLICT")
                conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(principal.tenant_id+':assets',))
                asset_limit=conn.execute(
                    'INSERT INTO platform.tenant_operating_limits(tenant_id) VALUES(%s) '
                    'ON CONFLICT(tenant_id) DO UPDATE SET tenant_id=excluded.tenant_id RETURNING max_assets',
                    (principal.tenant_id,),).fetchone()['max_assets']
                if conn.execute('SELECT count(*) AS n FROM platform.assets').fetchone()['n'] >= asset_limit:
                    raise HTTPException(429,'TENANT_QUOTA_EXCEEDED')
                row = conn.execute("INSERT INTO platform.assets(tenant_id,id,workspace_id,environment_id,asset_type,name,metadata) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                                   (principal.tenant_id, asset_id, *values)).fetchone()
            else:
                if existing and (existing["workspace_id"] != body.workspace_id or
                                 existing["environment_id"] != body.environment_id):
                    raise HTTPException(409,"PARENT_IMMUTABLE")
                row = conn.execute("UPDATE platform.assets SET workspace_id=%s,environment_id=%s,asset_type=%s,name=%s,metadata=%s,version=version+1 WHERE id=%s AND version=%s RETURNING *",
                                   (*values, asset_id, if_match)).fetchone()
                if not row:
                    raise HTTPException(409 if existing else 404, "VERSION_CONFLICT" if existing else "NOT_FOUND")
            audit(conn, principal, request.state.correlation_id, "asset.write", asset_id)
            return row

    @app.get("/v1/assets")
    def assets(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
               after: UUID | None = None, limit: int = Query(50, ge=1, le=100)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "tenant.read", str(workspace_id))
            return conn.execute("SELECT * FROM platform.assets WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id, after, after, limit)).fetchall()

    @app.delete("/v1/assets/{asset_id}")
    def delete_asset(asset_id: UUID, request: Request, if_match: int = Header(ge=1),
                     authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn,principal):
            row = require_row(conn.execute("SELECT * FROM platform.assets WHERE id=%s",(asset_id,)).fetchone())
            database.authorize(principal,"asset.manage",str(row["workspace_id"]))
            deleted = conn.execute("DELETE FROM platform.assets WHERE id=%s AND version=%s RETURNING id",(asset_id,if_match)).fetchone()
            if not deleted: raise HTTPException(409,"VERSION_CONFLICT")
            audit(conn,principal,request.state.correlation_id,"asset.delete",asset_id)
            return {"deleted":True}

    @app.put("/v1/tool-capabilities/{capability_record_id}")
    def put_capability(capability_record_id: UUID, body: CapabilityInput, request: Request,
                       authorization: str | None = Header(None), if_match: int = Header(0, ge=0)):
        errors = validate(body.document, "tool_capability")
        if errors:
            raise HTTPException(422, "INVALID_TOOL_CAPABILITY")
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            if body.document.get("environment") != env["kind"]:
                raise HTTPException(409,"ENVIRONMENT_SCOPE_MISMATCH")
            database.authorize(principal, "capability.manage", str(body.workspace_id), env["kind"])
            asset = require_row(conn.execute("SELECT asset_type,environment_id FROM platform.assets WHERE id=%s", (body.tool_asset_id,)).fetchone())
            if asset["asset_type"] != "tool" or asset["environment_id"] != body.environment_id:
                raise HTTPException(409, "INVALID_TOOL_ASSET")
            existing = conn.execute("SELECT * FROM platform.tool_capabilities WHERE id=%s FOR UPDATE", (capability_record_id,)).fetchone()
            values = (body.workspace_id, body.environment_id, body.tool_asset_id,
                      body.document["tool_id"], psycopg.types.json.Jsonb(body.document))
            if if_match == 0:
                if existing:
                    raise HTTPException(409, "VERSION_CONFLICT")
                row = conn.execute("INSERT INTO platform.tool_capabilities(tenant_id,id,workspace_id,environment_id,tool_asset_id,tool_id,document) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                                   (principal.tenant_id, capability_record_id, *values)).fetchone()
            else:
                if existing and (existing["workspace_id"] != body.workspace_id or
                                 existing["environment_id"] != body.environment_id or
                                 existing["tool_asset_id"] != body.tool_asset_id or
                                 existing["tool_id"] != body.document["tool_id"]):
                    raise HTTPException(409,"CAPABILITY_BINDING_IMMUTABLE")
                row = conn.execute("UPDATE platform.tool_capabilities SET workspace_id=%s,environment_id=%s,tool_asset_id=%s,tool_id=%s,document=%s,version=version+1 WHERE id=%s AND version=%s RETURNING *",
                                   (*values, capability_record_id, if_match)).fetchone()
                if not row:
                    raise HTTPException(409 if existing else 404, "VERSION_CONFLICT" if existing else "NOT_FOUND")
            event_id = uuid4()
            enqueue_event(conn, principal, namespace="capability", event_type="capability.changed",
                          priority="P2", payload={"event_id": str(event_id), "tenant_id": principal.tenant_id,
                          "environment_id": str(body.environment_id), "tool_id": body.document["tool_id"],
                          "version": row["version"]})
            audit(conn, principal, request.state.correlation_id, "capability.write", capability_record_id)
            return row

    @app.get("/v1/tool-capabilities")
    def capabilities(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                     after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"tenant.read",str(workspace_id))
            return conn.execute("SELECT * FROM platform.tool_capabilities WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.post("/v1/approval-requests", status_code=201)
    def request_approval(body: ApprovalInput, request: Request,
                         idempotency_key: str = Header(min_length=16, max_length=255),
                         authorization: str | None = Header(None)):
        now = datetime.now(timezone.utc)
        if body.expires_at <= now or body.expires_at > now + timedelta(hours=24):
            raise HTTPException(422, "INVALID_EXPIRY")
        if body.use_mode == "one_time" and body.max_uses != 1:
            raise HTTPException(422, "INVALID_USE_LIMIT")
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            database.authorize(principal, "approval.request", str(body.workspace_id), env["kind"])
            capability = require_row(conn.execute(
                "SELECT document FROM platform.tool_capabilities WHERE environment_id=%s AND tool_id=%s",
                (body.environment_id, body.tool_id),
            ).fetchone())
            if body.capability_id not in capability["document"]["capabilities"]:
                raise HTTPException(409, "CAPABILITY_SCOPE_MISMATCH")
            patterns = capability["document"].get("resource_patterns",[])
            if not patterns or not any(fnmatchcase(body.resource,pattern) for pattern in patterns):
                raise HTTPException(409,"RESOURCE_SCOPE_MISMATCH")
            high_risk = body.capability_id in {"payment.execute","secret.read","identity.admin","shell.execute"} or capability["document"]["sensitivity"] == "critical"
            required = max(body.required_approvals, 2 if high_risk else 1)
            existing = conn.execute("SELECT * FROM platform.approval_requests WHERE idempotency_key=%s", (idempotency_key,)).fetchone()
            if existing:
                expected = (body.workspace_id,body.environment_id,principal.identity_id,
                            body.tool_id,body.capability_id,body.resource,body.agent_id,
                            body.session_id,body.use_mode,body.max_uses,required,body.expires_at)
                actual = (existing["workspace_id"],existing["environment_id"],str(existing["requester_identity_id"]),
                          existing["tool_id"],existing["capability_id"],existing["resource"],existing["agent_id"],
                          existing["session_id"],existing["use_mode"],existing["max_uses"],
                          existing["required_approvals"],existing["expires_at"])
                if actual != expected:
                    raise HTTPException(409,"IDEMPOTENCY_CONFLICT")
                return existing
            request_id = uuid4()
            contract = {"schema_version":"1.0.0","request_id":str(request_id),
                "tenant_id":principal.tenant_id,"workspace_id":str(body.workspace_id),
                "environment_id":str(body.environment_id),"identity_id":principal.identity_id,
                "agent_id":body.agent_id,"session_id":body.session_id,"tool_id":body.tool_id,
                "capability_id":body.capability_id,"resource":body.resource,
                "expires_at":body.expires_at.isoformat(),"use_mode":body.use_mode,
                "max_uses":body.max_uses,"required_approvals":required,"created_at":now.isoformat()}
            if validate(contract,"approval_request"):
                raise HTTPException(422,"INVALID_APPROVAL_REQUEST")
            row = conn.execute(
                "INSERT INTO platform.approval_requests(tenant_id,id,workspace_id,environment_id,requester_identity_id,tool_id,capability_id,resource,agent_id,session_id,use_mode,max_uses,required_approvals,expires_at,idempotency_key) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                (principal.tenant_id, request_id, body.workspace_id, body.environment_id,
                 principal.identity_id, body.tool_id, body.capability_id, body.resource,
                 body.agent_id, body.session_id, body.use_mode, body.max_uses, required,
                 body.expires_at, idempotency_key),
            ).fetchone()
            audit(conn, principal, request.state.correlation_id, "approval.request", request_id)
            event_id = uuid4()
            enqueue_event(conn,principal,namespace="approval",event_type="approval.requested",
                          payload={"event_id":str(event_id),**contract},priority="P2")
            return row

    @app.get("/v1/approval-requests")
    def approval_requests(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                          after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"approval.request",str(workspace_id))
            return conn.execute("SELECT * FROM platform.approval_requests WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.post("/v1/approval-requests/{request_id}/decisions", status_code=201)
    def decide_approval(request_id: UUID, body: DecisionInput, request: Request,
                        authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            approval = require_row(conn.execute("SELECT * FROM platform.approval_requests WHERE id=%s FOR UPDATE", (request_id,)).fetchone())
            database.authorize(principal, "approval.decide", str(approval["workspace_id"]))
            if str(approval["requester_identity_id"]) == principal.identity_id:
                raise HTTPException(403, "SELF_APPROVAL_DENIED")
            decidable = ((body.decision == "REVOKE" and approval["status"] in ("pending","approved","exhausted"))
                         or (body.decision != "REVOKE" and approval["status"] in ("pending","approved")))
            if not decidable or approval["expires_at"] <= datetime.now(timezone.utc):
                raise HTTPException(409, "APPROVAL_NOT_DECIDABLE")
            decision_id = uuid4()
            try:
                decided_at = datetime.now(timezone.utc)
                row = conn.execute("INSERT INTO platform.approval_decisions(tenant_id,id,request_id,approver_identity_id,decision,reason) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *",
                                   (principal.tenant_id, decision_id, request_id, principal.identity_id, body.decision, body.reason)).fetchone()
            except psycopg.errors.UniqueViolation:
                raise HTTPException(409, "DUPLICATE_APPROVER")
            if body.decision in ("DENY", "REVOKE"):
                status = "denied" if body.decision == "DENY" else "revoked"
            else:
                count = conn.execute("SELECT count(*) AS n FROM platform.approval_decisions WHERE request_id=%s AND decision='APPROVE'", (request_id,)).fetchone()["n"]
                status = "approved" if count >= approval["required_approvals"] else "pending"
            conn.execute("UPDATE platform.approval_requests SET status=%s,version=version+1 WHERE id=%s", (status, request_id))
            if status == "revoked":
                conn.execute("UPDATE platform.approval_tokens SET revoked_at=now() WHERE request_id=%s AND revoked_at IS NULL", (request_id,))
            audit(conn, principal, request.state.correlation_id, "approval."+body.decision.lower(), request_id)
            decision_contract = {"schema_version":"1.0.0","decision_id":str(decision_id),
                "request_id":str(request_id),"tenant_id":principal.tenant_id,
                "approver_identity_id":principal.identity_id,"decision":body.decision,
                "reason":body.reason,"decided_at":decided_at.isoformat()}
            if validate(decision_contract,"approval_decision"):
                raise HTTPException(500,"INVALID_APPROVAL_DECISION")
            event_id = uuid4()
            enqueue_event(conn,principal,namespace="approval",event_type="approval.decided",
                          payload={"event_id":str(event_id),**decision_contract},priority="P2")
            if status == "revoked":
                nonces = [row["nonce"] for row in conn.execute("SELECT nonce FROM platform.approval_tokens WHERE request_id=%s",(request_id,)).fetchall()]
                revoke_event = uuid4()
                enqueue_event(conn,principal,namespace="approval",event_type="approval.revoked",
                              payload={"event_id":str(revoke_event),"tenant_id":principal.tenant_id,
                                       "request_id":str(request_id),"nonces":nonces},priority="P1")
            return {**row, "request_status": status}

    @app.post("/v1/approval-requests/{request_id}/tokens", status_code=201)
    def issue_approval_token(request_id: UUID, request: Request, response: Response,
                             authorization: str | None = Header(None)):
        if not approval_signing_key:
            raise HTTPException(503, "APPROVAL_SIGNING_UNAVAILABLE")
        with database.authenticated(authorization) as (conn, principal):
            approval = require_row(conn.execute("SELECT * FROM platform.approval_requests WHERE id=%s FOR UPDATE", (request_id,)).fetchone())
            database.authorize(principal, "approval.request", str(approval["workspace_id"]))
            if str(approval["requester_identity_id"]) != principal.identity_id:
                raise HTTPException(403, "FORBIDDEN")
            used = conn.execute("SELECT count(*) AS n FROM platform.approval_tokens WHERE request_id=%s", (request_id,)).fetchone()["n"]
            if approval["status"] != "approved" or approval["expires_at"] <= datetime.now(timezone.utc) or used >= approval["max_uses"]:
                raise HTTPException(409, "APPROVAL_TOKEN_UNAVAILABLE")
            nonce, token_id = secrets.token_urlsafe(32), str(uuid4())
            token = mint_approval_token(approval_signing_key, token_id=token_id,
                tenant_id=principal.tenant_id, tool_id=approval["tool_id"],
                capability_id=approval["capability_id"], expires_at=approval["expires_at"].timestamp(),
                nonce=nonce, agent_id=approval["agent_id"], session_id=approval["session_id"],
                identity_id=principal.identity_id, resource_scope=approval["resource"],
                approval_request_id=str(request_id))
            document = asdict(token)
            conn.execute("INSERT INTO platform.approval_tokens(tenant_id,id,request_id,nonce,token_document,expires_at) VALUES(%s,%s,%s,%s,%s,%s)",
                         (principal.tenant_id, token_id, request_id, nonce, psycopg.types.json.Jsonb(document), approval["expires_at"]))
            if used + 1 >= approval["max_uses"]:
                conn.execute("UPDATE platform.approval_requests SET status='exhausted',version=version+1 WHERE id=%s", (request_id,))
            audit(conn, principal, request.state.correlation_id, "approval.token.issue", UUID(token_id))
            response.headers["Cache-Control"] = "no-store"
            return document

    @app.put("/v1/findings/{finding_id}")
    def create_finding(finding_id: UUID, body: FindingInput, request: Request,
                       idempotency_key: str = Header(min_length=16, max_length=255),
                       authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            database.authorize(principal, "finding.manage", str(body.workspace_id), env["kind"])
            document = {**body.details,"schema_version":"1.0.0","finding_id":str(finding_id),
                "tenant_id":principal.tenant_id,"state":body.state,"root_cause":body.root_cause,
                "created_at":datetime.now(timezone.utc).isoformat(),
                "updated_at":datetime.now(timezone.utc).isoformat()}
            if validate(document, "finding"):
                raise HTTPException(422, "INVALID_FINDING")
            row = conn.execute("INSERT INTO platform.findings(tenant_id,id,workspace_id,environment_id,state,document) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *",
                               (principal.tenant_id,finding_id,body.workspace_id,body.environment_id,body.state,psycopg.types.json.Jsonb(document))).fetchone()
            audit(conn, principal, request.state.correlation_id, "finding.create", finding_id)
            event_id = uuid4()
            enqueue_event(conn,principal,namespace="finding",event_type="finding.created",
                          payload={"event_id":str(event_id),"tenant_id":principal.tenant_id,
                                   "finding_id":str(finding_id),"state":body.state},priority="P2")
            return row

    @app.get("/v1/findings")
    def findings(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                 after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"tenant.read",str(workspace_id))
            return conn.execute("SELECT * FROM platform.findings WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.post("/v1/findings/{finding_id}/transitions")
    def transition_finding(finding_id: UUID, body: FindingTransition, request: Request,
                           if_match: int = Header(ge=1), authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            finding = require_row(conn.execute("SELECT * FROM platform.findings WHERE id=%s FOR UPDATE", (finding_id,)).fetchone())
            database.authorize(principal, "finding.manage", str(finding["workspace_id"]))
            if body.state not in TRANSITIONS[finding["state"]]:
                raise HTTPException(409, "INVALID_FINDING_TRANSITION")
            document = dict(finding["document"])
            document["state"], document["updated_at"] = body.state, datetime.now(timezone.utc).isoformat()
            row = conn.execute("UPDATE platform.findings SET state=%s,document=%s,version=version+1,updated_at=now() WHERE id=%s AND version=%s RETURNING *",
                               (body.state,psycopg.types.json.Jsonb(document),finding_id,if_match)).fetchone()
            if not row:
                raise HTTPException(409, "VERSION_CONFLICT")
            audit(conn, principal, request.state.correlation_id, "finding.transition", finding_id)
            return row

    @app.get("/v1/policies")
    def policies(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                 after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"tenant.read",str(workspace_id))
            return conn.execute("SELECT * FROM platform.policies WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.put("/v1/policies/{policy_id}")
    def create_policy(policy_id: UUID, body: PolicyInput, request: Request,
                      authorization: str | None = Header(None)):
        if validate(body.source, "policy") or body.source.get("policy_id") != str(policy_id):
            raise HTTPException(422, "INVALID_POLICY")
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            database.authorize(principal, "policy.manage", str(body.workspace_id), env["kind"])
            existing = conn.execute("SELECT * FROM platform.policies WHERE id=%s",(policy_id,)).fetchone()
            if existing:
                if (existing["workspace_id"] == body.workspace_id and
                        existing["environment_id"] == body.environment_id and
                        existing["source_document"] == body.source):
                    return existing
                raise HTTPException(409,"VERSION_CONFLICT")
            row = conn.execute("INSERT INTO platform.policies(tenant_id,id,workspace_id,environment_id,policy_version,source_document) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *",
                               (principal.tenant_id,policy_id,body.workspace_id,body.environment_id,body.source["version"],psycopg.types.json.Jsonb(body.source))).fetchone()
            audit(conn, principal, request.state.correlation_id, "policy.create", policy_id)
            return row

    @app.get("/v1/evidence")
    def evidence(request: Request, workspace_id: UUID, authorization: str | None = Header(None),
                 after: UUID | None = None, limit: int = Query(50,ge=1,le=100)):
        with database.authenticated(authorization) as (conn,principal):
            database.authorize(principal,"evidence.read",str(workspace_id))
            return conn.execute("SELECT * FROM platform.evidence_objects WHERE workspace_id=%s AND (%s::uuid IS NULL OR id>%s::uuid) ORDER BY id LIMIT %s",
                                (workspace_id,after,after,limit)).fetchall()

    @app.post("/v1/policies/{policy_id}/publish")
    def publish_policy(policy_id: UUID, request: Request, if_match: int = Header(ge=1),
                       authorization: str | None = Header(None)):
        if not policy_signing_key:
            raise HTTPException(503, "POLICY_SIGNING_UNAVAILABLE")
        with database.authenticated(authorization) as (conn, principal):
            policy = require_row(conn.execute("SELECT * FROM platform.policies WHERE id=%s FOR UPDATE", (policy_id,)).fetchone())
            database.authorize(principal, "policy.manage", str(policy["workspace_id"]))
            if policy["version"] != if_match:
                raise HTTPException(409, "VERSION_CONFLICT")
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                         (principal.tenant_id+':policy:'+str(policy["environment_id"]),))
            if policy["status"] == "active" and policy["compiled_document"]:
                return policy
            compiled = compile_policy(dict(policy["source_document"]), key=policy_signing_key).to_dict()
            load_verified(compiled, key=policy_signing_key)
            conn.execute("UPDATE platform.policies SET status='retired' WHERE environment_id=%s AND status='active'", (policy["environment_id"],))
            row = conn.execute("UPDATE platform.policies SET compiled_document=%s,policy_hash=%s,signature=%s,status='active',activated_at=now(),version=version+1 WHERE id=%s RETURNING *",
                               (psycopg.types.json.Jsonb(compiled),compiled["policy_hash"],compiled["signature"],policy_id)).fetchone()
            event_id = uuid4()
            payload = {"schema_version":"1.0.0","event_id":str(event_id),"sequence":0,
                "namespace":"policy","keys":[str(policy["environment_id"])],
                "tenant_id":principal.tenant_id,"issued_at":datetime.now(timezone.utc).isoformat()}
            sequence = enqueue_event(conn, principal, namespace="policy", event_type="cache.invalidation", payload=payload)
            payload["sequence"] = sequence
            conn.execute("UPDATE platform.outbox SET payload=%s WHERE id=%s", (psycopg.types.json.Jsonb(payload),event_id))
            audit(conn, principal, request.state.correlation_id, "policy.publish", policy_id)
            return row

    @app.post("/v1/policies/{policy_id}/rollback")
    def rollback_policy(policy_id: UUID, request: Request, authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            target = require_row(conn.execute("SELECT * FROM platform.policies WHERE id=%s AND compiled_document IS NOT NULL FOR UPDATE", (policy_id,)).fetchone())
            database.authorize(principal, "policy.manage", str(target["workspace_id"]))
            if not policy_signing_key:
                raise HTTPException(503, "POLICY_SIGNING_UNAVAILABLE")
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                         (principal.tenant_id+':policy:'+str(target["environment_id"]),))
            load_verified(dict(target["compiled_document"]), key=policy_signing_key)
            conn.execute("UPDATE platform.policies SET status='retired' WHERE environment_id=%s AND status='active'", (target["environment_id"],))
            row = conn.execute("UPDATE platform.policies SET status='active',activated_at=now(),version=version+1 WHERE id=%s RETURNING *", (policy_id,)).fetchone()
            event_id = uuid4()
            payload = {"schema_version":"1.0.0","event_id":str(event_id),"sequence":0,
                "namespace":"policy","keys":[str(target["environment_id"])],"tenant_id":principal.tenant_id,
                "issued_at":datetime.now(timezone.utc).isoformat()}
            sequence = enqueue_event(conn, principal, namespace="policy", event_type="cache.invalidation", payload=payload)
            payload["sequence"] = sequence
            conn.execute("UPDATE platform.outbox SET payload=%s WHERE id=%s",(psycopg.types.json.Jsonb(payload),event_id))
            audit(conn, principal, request.state.correlation_id, "policy.rollback", policy_id)
            return row

    @app.post("/v1/evidence/uploads", status_code=201)
    def create_evidence_upload(body: UploadInput, request: Request, response: Response,
                               authorization: str | None = Header(None)):
        if object_store is None:
            raise HTTPException(503, "OBJECT_STORAGE_UNAVAILABLE")
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "evidence.read")
            try:
                url = object_store.create_upload(principal.tenant_id,body.object_key,
                    sha256=body.sha256,media_type=body.media_type,expires_s=300)
            except ValueError:
                raise HTTPException(422, "UNSAFE_OBJECT_KEY")
            response.headers["Cache-Control"] = "no-store"
            return {"upload_url":url,"expires_in":300}

    @app.post("/v1/evidence", status_code=201)
    def register_evidence(body: EvidenceInput, request: Request,
                          authorization: str | None = Header(None)):
        if object_store is None:
            raise HTTPException(503, "OBJECT_STORAGE_UNAVAILABLE")
        with database.authenticated(authorization) as (conn, principal):
            env = environment(conn, body.environment_id)
            if env["workspace_id"] != body.workspace_id:
                raise HTTPException(404, "NOT_FOUND")
            database.authorize(principal, "evidence.read", str(body.workspace_id), env["kind"])
            prefix = principal.tenant_id + "/"
            if not body.object_key.startswith(prefix) or ".." in body.object_key.split("/"):
                raise HTTPException(422, "UNSAFE_OBJECT_KEY")
            try:
                stored = object_store.head(principal.tenant_id, body.object_key)
            except (KeyError, ValueError):
                raise HTTPException(409, "EVIDENCE_OBJECT_NOT_VERIFIED")
            if (stored.size_bytes != body.size_bytes or stored.sha256 != body.object_hash.removeprefix("sha256:")
                    or stored.media_type != body.media_type):
                raise HTTPException(409, "EVIDENCE_OBJECT_MISMATCH")
            evidence_id = uuid4()
            document = {"schema_version":"1.0.0","evidence_id":str(evidence_id),
                "tenant_id":principal.tenant_id,"event_id":body.event_id,"trace_id":body.trace_id,
                "action_state":body.action_state,"sources":body.sources,"prev_hash":None,
                "created_at":datetime.now(timezone.utc).isoformat()}
            document["integrity_hash"] = evidence_integrity.content_hash(document)
            document["signature"] = evidence_integrity.sign(document,evidence_signing_key)
            if validate(document,"evidence"):
                raise HTTPException(422, "INVALID_EVIDENCE")
            row = conn.execute("INSERT INTO platform.evidence_objects(tenant_id,id,workspace_id,environment_id,event_id,object_key,media_type,size_bytes,object_hash,record_hash,signature,document) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                               (principal.tenant_id,evidence_id,body.workspace_id,body.environment_id,body.event_id,body.object_key,body.media_type,body.size_bytes,body.object_hash,document["integrity_hash"],document["signature"],psycopg.types.json.Jsonb(document))).fetchone()
            audit(conn, principal, request.state.correlation_id, "evidence.register", evidence_id)
            conn.execute(
                "INSERT INTO platform.usage_daily(tenant_id,usage_date,metric,amount) VALUES(%s,current_date,'evidence_bytes',%s) "
                "ON CONFLICT(tenant_id,usage_date,metric) DO UPDATE SET amount=platform.usage_daily.amount+excluded.amount",
                (principal.tenant_id,body.size_bytes),)
            enqueue_event(conn,principal,namespace='billing',event_type='billing.usage.recorded',priority='P5',payload={
                'event_id':str(uuid4()),'metric':'evidence_bytes','quantity':body.size_bytes,
                'occurred_at':datetime.now(timezone.utc).isoformat()})
            return row

    @app.get("/v1/audit")
    def read_audit(request: Request, authorization: str | None = Header(None),
                   after: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal, "audit.read")
            return conn.execute("SELECT * FROM platform.audit WHERE id>%s ORDER BY id LIMIT %s", (after,limit)).fetchall()

    @app.get("/v1/audit/verify")
    def verify_audit(request: Request, authorization: str | None = Header(None)):
        with database.authenticated(authorization) as (conn, principal):
            database.authorize(principal,"audit.read")
            ok = conn.execute("SELECT platform.verify_audit_chain(%s) AS ok",(principal.tenant_id,)).fetchone()["ok"]
            return {"valid":ok}
