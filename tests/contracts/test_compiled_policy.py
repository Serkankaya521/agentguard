"""Compiled policy: compile, sign/verify, tamper detection, rollback, evaluator parity."""
import unittest

import signing
from artifacts import CompiledPolicy, InvalidArtifact, PolicyArtifactStore, load_verified
from capability_registry import CapabilityResolution, ToolCapability
from compiler import compile_policy, default_compiled_policy, default_policy_source
from enums import ApprovalMode, Decision, Environment, ReasonCode, Sensitivity, SideEffect
from evaluator import evaluate
from optimizer import optimize
from validation import is_valid


class TestCompileAndSchema(unittest.TestCase):
    def test_default_compiles_and_is_schema_valid(self):
        c = default_compiled_policy()
        self.assertTrue(is_valid(c.to_dict(), "compiled_policy"))
        self.assertTrue(c.policy_hash.startswith("sha256:"))

    def test_source_is_schema_valid(self):
        self.assertTrue(is_valid(default_policy_source(), "policy"))


class TestSigning(unittest.TestCase):
    def test_hash_only_verifies(self):
        c = default_compiled_policy().to_dict()
        ok, _ = signing.verify(c, None)
        self.assertTrue(ok)

    def test_hmac_signature_roundtrip(self):
        c = compile_policy(default_policy_source(), key="k-123").to_dict()
        self.assertTrue(signing.verify(c, "k-123")[0])
        self.assertFalse(signing.verify(c, "wrong-key")[0])

    def test_tamper_detected(self):
        c = default_compiled_policy().to_dict()
        c["ruleset"]["critical_requires_approval"] = False  # tamper
        ok, reason = signing.verify(c, None)
        self.assertFalse(ok)
        with self.assertRaises(InvalidArtifact):
            load_verified(c)


class TestArtifactStore(unittest.TestCase):
    def test_publish_active_rollback(self):
        store = PolicyArtifactStore()
        v1 = default_compiled_policy()
        store.publish(v1)
        self.assertEqual(store.active().policy_hash, v1.policy_hash)
        src2 = default_policy_source()
        src2["version"] = "test/2.0.0"
        src2["ruleset"]["critical_requires_approval"] = False
        v2 = compile_policy(src2)
        store.publish(v2)
        self.assertEqual(store.active().policy_version, "test/2.0.0")
        store.rollback()
        self.assertEqual(store.active().policy_hash, v1.policy_hash)

    def test_incompatible_runtime_refused(self):
        src = default_policy_source()
        c = compile_policy(src, min_runtime="runtime-gateway/9.9.9").to_dict()
        with self.assertRaises(InvalidArtifact):
            load_verified(c, runtime_version="runtime-gateway/0.1.0-a1")

    def test_schema_invalid_refused(self):
        c = default_compiled_policy().to_dict()
        c.pop("ruleset")
        with self.assertRaises(InvalidArtifact):
            load_verified(c)


class TestEvaluatorParity(unittest.TestCase):
    def _ruleset(self):
        return optimize(default_compiled_policy())

    def test_low_risk_allow(self):
        rec = ToolCapability(tool_id="t", capabilities=("mcp.invoke",),
                             side_effect=SideEffect.NONE, sensitivity=Sensitivity.LOW,
                             approval_mode=ApprovalMode.NEVER, version="1")
        res = CapabilityResolution(known=True, record=rec, capability_id="mcp.invoke", mismatch=False)
        d = evaluate(self._ruleset(), environment=Environment.PRODUCTION,
                     resolution=res, resource_scope=None)
        self.assertEqual(d.decision, Decision.ALLOW)

    def test_unknown_blocked_in_prod(self):
        res = CapabilityResolution(known=False, record=None, capability_id=None, mismatch=False)
        d = evaluate(self._ruleset(), environment=Environment.PRODUCTION,
                     resolution=res, resource_scope=None)
        self.assertEqual(d.decision, Decision.BLOCK)
        self.assertIn(ReasonCode.BLOCKED_UNKNOWN_CAPABILITY_PROD, d.reason_codes)


if __name__ == "__main__":
    unittest.main()
