"""Stdlib test runner (no pytest required). Deterministic path priority; see conftest.py."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ORDER = (
    "apps/runtime-gateway/src", "packages/policy/src", "packages/detectors/src",
    "packages/aegis/src", "packages/attack-graph/src", "packages/contracts/src",
    "packages/evidence/src", "packages/domain/src", "apps/worker/src",
    "tests/contracts", "apps/runtime-gateway/tests",
)
sys.path[:0] = [str(ROOT / p) for p in ORDER]

import test_contracts, test_pipeline, test_compiled_policy, test_cache, test_resilience  # noqa: E402
import test_detectors, test_trajectory, test_execution_gate, test_a3_pipeline  # noqa: E402

_MODULES = [test_contracts, test_pipeline, test_compiled_policy, test_cache, test_resilience,
            test_detectors, test_trajectory, test_execution_gate, test_a3_pipeline]

import test_evidence, test_aegis, test_attack_graph, test_a4_worker  # noqa: E402
import test_a5_redteam, test_a5_regression  # noqa: E402
import test_a6_twin, test_a6_governance, test_a6_integration  # noqa: E402
import test_a7, test_a7_finish  # noqa: E402
import test_live_target, test_approval_revocation  # noqa: E402
import test_analytics_publisher, test_adapters, test_side_effects  # noqa: E402
import test_distributed_kill_switch, test_corpus_promotion  # noqa: E402
_MODULES += [test_evidence, test_aegis, test_attack_graph, test_a4_worker]
_MODULES += [test_a5_redteam, test_a5_regression]
_MODULES += [test_a6_twin, test_a6_governance, test_a6_integration]
_MODULES += [test_a7, test_a7_finish]
_MODULES += [test_live_target, test_approval_revocation, test_analytics_publisher, test_adapters, test_side_effects]
_MODULES += [test_distributed_kill_switch, test_corpus_promotion]

loader = unittest.TestLoader()
suite = unittest.TestSuite()
for m in _MODULES:
    suite.addTests(loader.loadTestsFromModule(m))

if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
