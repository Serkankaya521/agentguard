"""Stdlib test runner for Sprint A1 (no pytest required).

Adds the A1 source roots and test directories to sys.path, then runs the
unittest suites. Usage: `python3 tests/test_runner.py`.
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATHS = (
    "packages/domain/src",
    "packages/contracts/src",
    "packages/policy/src",
    "packages/detectors/src",
    "apps/runtime-gateway/src",
    "tests/contracts",
    "apps/runtime-gateway/tests",
)
for p in PATHS:
    sys.path.insert(0, str(ROOT / p))

import test_contracts  # noqa: E402  (tests/contracts)
import test_pipeline  # noqa: E402  (apps/runtime-gateway/tests)
import test_compiled_policy  # noqa: E402  (tests/contracts)
import test_cache  # noqa: E402  (apps/runtime-gateway/tests)
import test_resilience  # noqa: E402  (apps/runtime-gateway/tests)
import test_detectors  # noqa: E402
import test_trajectory  # noqa: E402
import test_execution_gate  # noqa: E402
import test_a3_pipeline  # noqa: E402

loader = unittest.TestLoader()
suite = unittest.TestSuite()
suite.addTests(loader.loadTestsFromModule(test_contracts))
suite.addTests(loader.loadTestsFromModule(test_pipeline))
suite.addTests(loader.loadTestsFromModule(test_compiled_policy))
suite.addTests(loader.loadTestsFromModule(test_cache))
suite.addTests(loader.loadTestsFromModule(test_resilience))
suite.addTests(loader.loadTestsFromModule(test_detectors))
suite.addTests(loader.loadTestsFromModule(test_trajectory))
suite.addTests(loader.loadTestsFromModule(test_execution_gate))
suite.addTests(loader.loadTestsFromModule(test_a3_pipeline))

if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
