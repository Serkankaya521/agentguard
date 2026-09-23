"""End-to-end: an approval.revoked event denies the token at the ExecutionGate.

Uses the real control-plane ApprovalReplayGuard over fakeredis and the real
runtime ExecutionGate, so the two agree on the Redis key scheme.
"""
import fakeredis
import pytest

from approval_revocation import ApprovalRevocationProcessor
from enums import (ActionState, CacheSource, Decision, Environment, FailMode,
                   IdentityType, ReasonCode)
from decisions import RuntimeDecision
from execution_gate import DecisionSigner, ExecutionGate, mint_approval_token
from platform_cache import ApprovalReplayGuard
from security_event import SecurityEvent
from tenant import TenantContext

KEY = "gate-key"


def tenant():
    return TenantContext(tenant_id="A", workspace_id="w", environment_id="e",
                         environment=Environment.PRODUCTION, identity_id="i",
                         identity_type=IdentityType.SERVICE, session_id="s1", agent_id="ag1")


def event(event_id):
    return SecurityEvent(event_id=event_id, trace_id="tr", occurred_at="2026-09-12T00:00:00Z",
                         source=__import__("enums").EventSource.MCP,
                         action_state=ActionState.PROPOSED, tenant=tenant(),
                         tool_id="pay", payload_hash="sha256:x")


def signed(event_id):
    d = RuntimeDecision(
        decision_id="d-" + event_id, tenant_id="A", event_id=event_id, trace_id="tr",
        policy_version="builtin/1.0.0", policy_hash="sha256:p", runtime_version="rt",
        risk_score=0.1, reason_codes=(ReasonCode.ALLOWED_LOW_RISK,),
        cache_source=CacheSource.COMPUTED, latency_us=1, trajectory_version=0,
        decision=Decision.REQUIRE_APPROVAL, fail_mode=FailMode.FAIL_CLOSED,
        action_state=ActionState.PROPOSED, capability_id="payment.execute")
    return DecisionSigner(KEY).sign(d, ttl_s=1e9, now=100.0)


@pytest.fixture
def guard():
    return ApprovalReplayGuard(fakeredis.FakeRedis())


def token(nonce):
    return mint_approval_token(KEY, token_id="t", tenant_id="A", tool_id="pay",
                               capability_id="payment.execute", expires_at=200.0, nonce=nonce)


def test_revoked_nonce_is_denied_at_the_gate(guard):
    gate = ExecutionGate(KEY, clock=lambda: 100.0, replay_guard=guard)
    tok = token("nonce-live")
    ApprovalRevocationProcessor(guard, clock=lambda: 100.0).process_event(
        {"event_type": "approval.revoked", "tenant_id": "A", "request_id": "r1",
         "nonces": ["nonce-live"]})
    out = gate.authorize(signed("e1"), event("e1"), tok)
    assert not out.permitted
    assert ReasonCode.EXEC_APPROVAL_REPLAY in out.reason_codes


def test_unrevoked_token_still_works_once(guard):
    gate = ExecutionGate(KEY, clock=lambda: 100.0, replay_guard=guard)
    ApprovalRevocationProcessor(guard, clock=lambda: 100.0).process_event(
        {"event_type": "approval.revoked", "tenant_id": "A", "nonces": ["other"]})
    out = gate.authorize(signed("e1"), event("e1"), token("nonce-ok"))
    assert out.permitted
    assert out.action_state == ActionState.APPROVED


def test_revocation_is_cross_instance(guard):
    # Instance 1 revokes; a *different* gate instance sharing the guard denies.
    ApprovalRevocationProcessor(guard, clock=lambda: 100.0).process_event(
        {"event_type": "approval.revoked", "tenant_id": "A", "nonces": ["shared"]})
    other_gate = ExecutionGate(KEY, clock=lambda: 100.0, replay_guard=guard)
    out = other_gate.authorize(signed("e2"), event("e2"), token("shared"))
    assert ReasonCode.EXEC_APPROVAL_REPLAY in out.reason_codes
