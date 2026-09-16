"""Execution Gate: integrity, expiry, correlation, replay, approval token."""
import unittest

from decisions import RuntimeDecision
from enums import ActionState, CacheSource, Decision, FailMode, IdentityType, Environment, ReasonCode
from execution_gate import DecisionSigner, ExecutionGate, SignedDecision, mint_approval_token
from security_event import SecurityEvent
from tenant import TenantContext
from enums import EventSource

KEY = "gate-key"


def tenant(**kw):
    d = dict(tenant_id="A", workspace_id="w", environment_id="e",
             environment=Environment.PRODUCTION, identity_id="i",
             identity_type=IdentityType.SERVICE, session_id="s1", agent_id="ag1")
    d.update(kw)
    return TenantContext(**d)


def event(event_id="e1", tool_id="pay", **kw):
    resource_scope = kw.pop("resource_scope", None)
    return SecurityEvent(event_id=event_id, trace_id="tr", occurred_at="2026-09-12T00:00:00Z",
                         source=EventSource.MCP, action_state=ActionState.PROPOSED,
                         tenant=tenant(**kw), tool_id=tool_id, payload_hash="sha256:x",
                         resource_scope=resource_scope)


def decision(dec=Decision.ALLOW, event_id="e1", capability_id="mcp.invoke"):
    return RuntimeDecision(
        decision_id="d-" + dec.value + "-" + event_id, tenant_id="A", event_id=event_id,
        trace_id="tr", policy_version="builtin/1.0.0", policy_hash="sha256:p",
        runtime_version="rt", risk_score=0.1, reason_codes=(ReasonCode.ALLOWED_LOW_RISK,),
        cache_source=CacheSource.COMPUTED, latency_us=1, trajectory_version=0,
        decision=dec, fail_mode=FailMode.FAIL_CLOSED, action_state=ActionState.PROPOSED,
        capability_id=capability_id)


class TestExecutionGate(unittest.TestCase):
    def setUp(self):
        self.signer = DecisionSigner(KEY)

    def test_allow_executes_once_then_replay_blocked(self):
        gate = ExecutionGate(KEY)
        sd = self.signer.sign(decision())
        out = gate.authorize(sd, event())
        self.assertTrue(out.permitted)
        self.assertEqual(out.action_state, ActionState.EXECUTED)
        out2 = gate.authorize(sd, event())
        self.assertFalse(out2.permitted)
        self.assertIn(ReasonCode.EXEC_REPLAY_DETECTED, out2.reason_codes)

    def test_tampered_decision_rejected(self):
        sd = self.signer.sign(decision())
        forged = SignedDecision(decision(dec=Decision.ALLOW, event_id="e1"),
                                sd.issued_at, sd.ttl_s, sd.signature)
        # change capability after signing -> signature no longer matches
        forged = SignedDecision(
            RuntimeDecision(**{**forged.decision.__dict__, "capability_id": "identity.admin"}),
            sd.issued_at, sd.ttl_s, sd.signature)
        out = ExecutionGate(KEY).authorize(forged, event())
        self.assertIn(ReasonCode.EXEC_DECISION_INVALID_SIGNATURE, out.reason_codes)

    def test_expired_decision(self):
        clock = [1000.0]
        gate = ExecutionGate(KEY, clock=lambda: clock[0])
        sd = self.signer.sign(decision(), ttl_s=5.0, now=1000.0)
        clock[0] = 1010.0
        out = gate.authorize(sd, event())
        self.assertIn(ReasonCode.EXEC_DECISION_EXPIRED, out.reason_codes)

    def test_correlation_mismatch(self):
        sd = self.signer.sign(decision(event_id="e1"))
        out = ExecutionGate(KEY).authorize(sd, event(event_id="DIFFERENT"))
        self.assertIn(ReasonCode.EXEC_SCOPE_MISMATCH, out.reason_codes)

    def test_block_denied(self):
        sd = self.signer.sign(decision(dec=Decision.BLOCK))
        out = ExecutionGate(KEY).authorize(sd, event())
        self.assertFalse(out.permitted)
        self.assertEqual(out.action_state, ActionState.BLOCKED)

    def test_sandbox_permitted(self):
        sd = self.signer.sign(decision(dec=Decision.SANDBOX))
        out = ExecutionGate(KEY).authorize(sd, event())
        self.assertTrue(out.permitted and out.sandbox)

    def test_require_approval_needs_valid_token(self):
        gate = ExecutionGate(KEY, clock=lambda: 100.0)
        sd = self.signer.sign(decision(dec=Decision.REQUIRE_APPROVAL, capability_id="payment.execute"),
                              ttl_s=1e9, now=100.0)
        # missing token
        self.assertFalse(gate.authorize(sd, event(tool_id="pay")).permitted)
        # valid token
        tok = mint_approval_token(KEY, token_id="tk1", tenant_id="A", tool_id="pay",
                                  capability_id="payment.execute", expires_at=200.0, nonce="n1")
        out = gate.authorize(sd, event(tool_id="pay"), approval_token=tok)
        self.assertTrue(out.permitted)
        self.assertEqual(out.action_state, ActionState.APPROVED)

    def test_approval_scope_and_replay_and_expiry(self):
        gate = ExecutionGate(KEY, clock=lambda: 100.0)
        def fresh_sd(eid):
            return DecisionSigner(KEY).sign(
                decision(dec=Decision.REQUIRE_APPROVAL, event_id=eid, capability_id="payment.execute"),
                ttl_s=1e9, now=100.0)
        # scope mismatch (wrong tool)
        bad = mint_approval_token(KEY, token_id="t", tenant_id="A", tool_id="OTHER",
                                  capability_id="payment.execute", expires_at=200.0, nonce="nx")
        self.assertIn(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH,
                      gate.authorize(fresh_sd("e1"), event(event_id="e1", tool_id="pay"), bad).reason_codes)
        # expired token
        exp = mint_approval_token(KEY, token_id="t", tenant_id="A", tool_id="pay",
                                  capability_id="payment.execute", expires_at=50.0, nonce="ny")
        self.assertIn(ReasonCode.EXEC_APPROVAL_EXPIRED,
                      gate.authorize(fresh_sd("e2"), event(event_id="e2", tool_id="pay"), exp).reason_codes)
        # nonce replay
        tok = mint_approval_token(KEY, token_id="t", tenant_id="A", tool_id="pay",
                                  capability_id="payment.execute", expires_at=200.0, nonce="nonce-reuse")
        self.assertTrue(gate.authorize(fresh_sd("e3"), event(event_id="e3", tool_id="pay"), tok).permitted)
        self.assertIn(ReasonCode.EXEC_APPROVAL_REPLAY,
                      gate.authorize(fresh_sd("e4"), event(event_id="e4", tool_id="pay"), tok).reason_codes)

    def test_approval_identity_resource_and_cross_instance_replay(self):
        class Guard:
            used = set()
            def consume(self, tenant_id, nonce, ttl_s):
                key = (tenant_id,nonce)
                if key in self.used: return False
                self.used.add(key); return True
        token = mint_approval_token(KEY,token_id="scoped",tenant_id="A",tool_id="pay",
            capability_id="payment.execute",expires_at=200,nonce="global-nonce",
            identity_id="i",resource_scope="invoice/1",approval_request_id="request-1")
        def signed(event_id):
            return DecisionSigner(KEY).sign(decision(dec=Decision.REQUIRE_APPROVAL,
                event_id=event_id,capability_id="payment.execute"),ttl_s=1e9,now=100)
        guard = Guard()
        first = ExecutionGate(KEY,clock=lambda:100,replay_guard=guard)
        second = ExecutionGate(KEY,clock=lambda:100,replay_guard=guard)
        self.assertFalse(first.authorize(signed("scope-wrong"),event(event_id="scope-wrong",resource_scope="invoice/2"),token).permitted)
        self.assertTrue(first.authorize(signed("scope-ok"),event(event_id="scope-ok",resource_scope="invoice/1"),token).permitted)
        self.assertIn(ReasonCode.EXEC_APPROVAL_REPLAY,
            second.authorize(signed("scope-replay"),event(event_id="scope-replay",resource_scope="invoice/1"),token).reason_codes)


if __name__ == "__main__":
    unittest.main()
