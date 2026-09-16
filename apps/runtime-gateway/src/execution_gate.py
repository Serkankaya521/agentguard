"""Execution Gate: enforces only a valid, signed RuntimeDecision (task plan 15).

Checks: decision signature (integrity/TOCTOU), decision expiry, tenant/tool/event
correlation, replay prevention (a decision authorizes one execution), approval
token scope + one-time use, and sandbox/redact conditions. Keeps blocked and
executed as distinct outcomes - AgentGuard must never conflate "blocked" with
"a mutation happened at the target".

The gate authorizes execution; the integration performs the actual tool call.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from decisions import RuntimeDecision  # packages/domain/src
from enums import ActionState, Decision, ReasonCode
from serialization import canonical_json, to_jsonable  # packages/contracts/src


def _hmac(key, payload: str) -> str:
    kb = key if isinstance(key, bytes) else str(key).encode("utf-8")
    return "hmac-sha256:" + hmac.new(kb, payload.encode("utf-8"), hashlib.sha256).hexdigest()


# --- signed decision -------------------------------------------------------
@dataclass(frozen=True)
class SignedDecision:
    decision: RuntimeDecision
    issued_at: float
    ttl_s: float
    signature: str


def _decision_payload(decision: RuntimeDecision, issued_at: float, ttl_s: float) -> str:
    return canonical_json({"d": to_jsonable(decision), "iat": issued_at, "ttl": ttl_s})


class DecisionSigner:
    def __init__(self, key) -> None:
        self._key = key

    def sign(self, decision: RuntimeDecision, *, ttl_s: float = 5.0,
             now: Optional[float] = None) -> SignedDecision:
        issued = time.time() if now is None else now
        return SignedDecision(decision, issued, ttl_s,
                              _hmac(self._key, _decision_payload(decision, issued, ttl_s)))

    def verify(self, sd: SignedDecision) -> bool:
        want = _hmac(self._key, _decision_payload(sd.decision, sd.issued_at, sd.ttl_s))
        return hmac.compare_digest(sd.signature, want)


# --- approval token --------------------------------------------------------
@dataclass(frozen=True)
class ApprovalToken:
    token_id: str
    tenant_id: str
    tool_id: str
    capability_id: Optional[str]
    expires_at: float
    nonce: str
    signature: str
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    identity_id: Optional[str] = None
    resource_scope: Optional[str] = None
    approval_request_id: Optional[str] = None


def _token_payload(t: ApprovalToken) -> str:
    return canonical_json({
        "tid": t.token_id, "tenant": t.tenant_id, "tool": t.tool_id,
        "cap": t.capability_id, "exp": t.expires_at, "nonce": t.nonce,
        "agent": t.agent_id, "session": t.session_id, "identity": t.identity_id,
        "resource": t.resource_scope, "request": t.approval_request_id})


def mint_approval_token(key, *, token_id, tenant_id, tool_id, capability_id, expires_at,
                        nonce, agent_id=None, session_id=None, identity_id=None,
                        resource_scope=None, approval_request_id=None) -> ApprovalToken:
    t = ApprovalToken(token_id, tenant_id, tool_id, capability_id, expires_at, nonce,
                      "", agent_id, session_id, identity_id, resource_scope,
                      approval_request_id)
    return ApprovalToken(token_id, tenant_id, tool_id, capability_id, expires_at, nonce,
                         _hmac(key, _token_payload(t)), agent_id, session_id, identity_id,
                         resource_scope, approval_request_id)


# --- outcome ---------------------------------------------------------------
@dataclass(frozen=True)
class ExecutionOutcome:
    permitted: bool
    action_state: ActionState
    reason_codes: tuple[ReasonCode, ...]
    sandbox: bool = False
    redact: bool = False


_NEEDS_APPROVAL = {Decision.REQUIRE_APPROVAL, Decision.STEP_UP_AUTH}


class ExecutionGate:
    def __init__(self, key, *, clock=None, replay_window: int = 100_000,
                 replay_guard=None) -> None:
        self._signer = DecisionSigner(key)
        self._key = key
        self._clock = clock or time.time
        self._replay_guard = replay_guard
        self._used_decisions: deque = deque(maxlen=replay_window)
        self._used_decisions_set: set[str] = set()
        self._used_nonces: deque = deque(maxlen=replay_window)
        self._used_nonces_set: set[str] = set()

    def _deny(self, reason: ReasonCode) -> ExecutionOutcome:
        return ExecutionOutcome(False, ActionState.BLOCKED, (ReasonCode.EXEC_GATE_DENIED, reason))

    def _mark_decision(self, decision_id: str) -> None:
        self._used_decisions.append(decision_id)
        self._used_decisions_set.add(decision_id)
        while len(self._used_decisions_set) > self._used_decisions.maxlen:
            self._used_decisions_set.discard(self._used_decisions.popleft())

    def _mark_nonce(self, nonce: str) -> None:
        self._used_nonces.append(nonce)
        self._used_nonces_set.add(nonce)
        while len(self._used_nonces_set) > self._used_nonces.maxlen:
            self._used_nonces_set.discard(self._used_nonces.popleft())

    def authorize(self, signed: SignedDecision, event,
                  approval_token: Optional[ApprovalToken] = None) -> ExecutionOutcome:
        d = signed.decision
        now = self._clock()

        # 1) integrity / TOCTOU
        if not self._signer.verify(signed):
            return self._deny(ReasonCode.EXEC_DECISION_INVALID_SIGNATURE)
        # 2) expiry
        if now > signed.issued_at + signed.ttl_s:
            return self._deny(ReasonCode.EXEC_DECISION_EXPIRED)
        # 3) correlation: decision must match the event it is being applied to
        if d.event_id != event.event_id or d.tenant_id != event.tenant.tenant_id:
            return self._deny(ReasonCode.EXEC_SCOPE_MISMATCH)
        # 4) replay: a decision authorizes exactly one execution
        if d.decision_id in self._used_decisions_set:
            return self._deny(ReasonCode.EXEC_REPLAY_DETECTED)

        if d.decision == Decision.BLOCK:
            return self._deny(ReasonCode.EXEC_GATE_DENIED)

        if d.decision == Decision.ALLOW:
            self._mark_decision(d.decision_id)
            return ExecutionOutcome(True, ActionState.EXECUTED, (ReasonCode.EXEC_GATE_ALLOWED,))

        if d.decision == Decision.SANDBOX:
            self._mark_decision(d.decision_id)
            return ExecutionOutcome(True, ActionState.EXECUTED,
                                    (ReasonCode.EXEC_GATE_ALLOWED, ReasonCode.EXEC_SANDBOX_REQUIRED),
                                    sandbox=True)

        if d.decision == Decision.REDACT:
            self._mark_decision(d.decision_id)
            return ExecutionOutcome(True, ActionState.EXECUTED, (ReasonCode.EXEC_GATE_ALLOWED,),
                                    redact=True)

        if d.decision in _NEEDS_APPROVAL:
            outcome = self._authorize_with_token(d, event, approval_token, now)
            if outcome.permitted:
                self._mark_decision(d.decision_id)
            return outcome

        # ASYNC_DEEP_ANALYSIS and anything else: hold, do not execute.
        return ExecutionOutcome(False, ActionState.PROPOSED, (ReasonCode.EXEC_APPROVAL_REQUIRED,))

    def _authorize_with_token(self, d: RuntimeDecision, event,
                              token: Optional[ApprovalToken], now: float) -> ExecutionOutcome:
        if token is None:
            return ExecutionOutcome(False, ActionState.PROPOSED, (ReasonCode.EXEC_APPROVAL_REQUIRED,))
        # signature
        want = _hmac(self._key, _token_payload(token))
        if not hmac.compare_digest(token.signature, want):
            return self._deny(ReasonCode.EXEC_APPROVAL_INVALID)
        # expiry
        if now > token.expires_at:
            return self._deny(ReasonCode.EXEC_APPROVAL_EXPIRED)
        # scope match
        if (token.tenant_id != event.tenant.tenant_id
                or token.tool_id != event.tool_id
                or token.capability_id != d.capability_id):
            return self._deny(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH)
        if token.session_id is not None and token.session_id != event.tenant.session_id:
            return self._deny(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH)
        if token.agent_id is not None and token.agent_id != event.tenant.agent_id:
            return self._deny(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH)
        if token.identity_id is not None and token.identity_id != event.tenant.identity_id:
            return self._deny(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH)
        if token.resource_scope is not None and token.resource_scope != event.resource_scope:
            return self._deny(ReasonCode.EXEC_APPROVAL_SCOPE_MISMATCH)
        # one-time use
        if token.nonce in self._used_nonces_set:
            return self._deny(ReasonCode.EXEC_APPROVAL_REPLAY)
        if self._replay_guard is not None:
            ttl_s = max(1, int(token.expires_at - now))
            if not self._replay_guard.consume(token.tenant_id,token.nonce,ttl_s=ttl_s):
                return self._deny(ReasonCode.EXEC_APPROVAL_REPLAY)
        self._mark_nonce(token.nonce)
        return ExecutionOutcome(True, ActionState.APPROVED,
                                (ReasonCode.EXEC_GATE_ALLOWED,))
