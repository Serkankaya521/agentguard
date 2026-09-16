"""Developer B shared-contract publication and compatibility tests."""
from datetime import datetime, timezone

from validation import is_valid, schema_version


def now():
    return datetime.now(timezone.utc).isoformat()


def test_platform_contracts_are_published_v1():
    for name in ("approval_request", "approval_decision", "job_envelope"):
        assert schema_version(name) == "1.0.0"


def test_approval_request_scope_is_explicit():
    payload = {
        "schema_version": "1.0.0", "request_id": "r1", "tenant_id": "t1",
        "workspace_id": "w1", "environment_id": "e1", "identity_id": "u1",
        "agent_id": "a1", "session_id": "s1", "tool_id": "payments",
        "capability_id": "payment.execute", "resource": "account/1",
        "expires_at": now(), "use_mode": "one_time", "max_uses": 1,
        "required_approvals": 2, "created_at": now(),
    }
    assert is_valid(payload, "approval_request")
    payload["tenant_override"] = "evil"
    assert not is_valid(payload, "approval_request")


def test_approval_decision_and_job_envelope_validate():
    decision = {
        "schema_version": "1.0.0", "decision_id": "d1", "request_id": "r1",
        "tenant_id": "t1", "approver_identity_id": "u2",
        "decision": "APPROVE", "reason": None, "decided_at": now(),
    }
    assert is_valid(decision, "approval_decision")
    job = {
        "schema_version": "1.0.0", "job_id": "j1", "tenant_id": "t1",
        "workspace_id": "w1", "environment_id": "e1", "job_type": "report",
        "priority": "P4", "attempt": 0, "max_attempts": 5,
        "created_at": now(), "not_before": None, "correlation_id": "c1",
        "payload": {"report_id": "x"},
    }
    assert is_valid(job, "job_envelope")
    job["priority"] = "P0"
    assert not is_valid(job, "job_envelope")
