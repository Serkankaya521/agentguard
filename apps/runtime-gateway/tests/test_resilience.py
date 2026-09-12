"""Circuit breaker, latency budget, and dependency-failure fail mode."""
import unittest

from capability_registry import CapabilityRegistry, ToolCapability
from enums import ActionState, ApprovalMode, Decision, FailMode, ReasonCode, Sensitivity, SideEffect
from hot_path import latency_budget
from hot_path.circuit_breaker import CircuitBreaker, CircuitOpen
from policy_enforcement import RuntimeGatewayPipeline


class TestCircuitBreaker(unittest.TestCase):
    def test_opens_then_recovers(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=2, reset_timeout_s=5.0, clock=lambda: t[0])

        def boom():
            raise RuntimeError("dep down")

        for _ in range(2):
            with self.assertRaises(RuntimeError):
                cb.call(boom)
        self.assertEqual(cb.state, CircuitBreaker.OPEN)
        with self.assertRaises(CircuitOpen):
            cb.call(lambda: 1)
        t[0] = 10.0  # past reset -> half-open trial
        self.assertEqual(cb.call(lambda: 42), 42)
        self.assertEqual(cb.state, CircuitBreaker.CLOSED)

    def test_half_open_failure_reopens(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=1, reset_timeout_s=5.0, clock=lambda: t[0])
        with self.assertRaises(RuntimeError):
            cb.call(lambda: (_ for _ in ()).throw(RuntimeError()))
        self.assertEqual(cb.state, CircuitBreaker.OPEN)
        t[0] = 10.0
        with self.assertRaises(RuntimeError):
            cb.call(lambda: (_ for _ in ()).throw(RuntimeError()))
        self.assertEqual(cb.state, CircuitBreaker.OPEN)


class TestLatencyBudget(unittest.TestCase):
    def test_deadline_basic(self):
        d = latency_budget.start(20_000)
        self.assertFalse(d.exceeded())
        self.assertGreaterEqual(d.elapsed_us(), 0)
        self.assertLessEqual(d.remaining_us(), 20_000)


class _FailingRegistry(CapabilityRegistry):
    def resolve(self, tool_id, declared_capability_id):
        raise RuntimeError("capability source unavailable")


class TestDependencyFailMode(unittest.TestCase):
    def test_dependency_failure_fails_closed(self):
        pipe = RuntimeGatewayPipeline(
            _FailingRegistry(), breaker=CircuitBreaker(failure_threshold=1))
        raw = {"event_id": "e", "trace_id": "t", "tool_id": "secret_reader",
               "declared_capability_id": "secret.read",
               "tenant": {"schema_version": "1.0.0", "tenant_id": "A", "workspace_id": "w",
                          "environment_id": "e", "environment": "production",
                          "identity_id": "i", "identity_type": "service"}}
        d = pipe.process(raw, "mcp")
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertEqual(d.fail_mode, FailMode.FAIL_CLOSED)
        self.assertIn(ReasonCode.FAIL_CLOSED_DEPENDENCY, d.reason_codes)
        self.assertEqual(d.action_state, ActionState.BLOCKED)


if __name__ == "__main__":
    unittest.main()
