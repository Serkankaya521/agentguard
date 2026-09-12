"""pytest bootstrap: expose A1 source roots on sys.path.

Provisional test-time wiring. A proper workspace packaging decision (editable
installs / per-package pyproject, resolving hyphenated app dirs and the future
contracts/evidence `validation.py` namespace overlap) is a shared coordination
item with Developer B - see the Sprint A1 handoff.
"""
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
_SRC_ROOTS = (
    "packages/domain/src",
    "packages/contracts/src",
    "packages/policy/src",
    "apps/runtime-gateway/src",
)
for _p in _SRC_ROOTS:
    _full = str(_ROOT / _p)
    if _full not in sys.path:
        sys.path.insert(0, _full)
