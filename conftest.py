"""pytest bootstrap: expose source roots on sys.path in a DETERMINISTIC priority
order so flat-layout module-name overlaps resolve predictably:

- packages/contracts/src BEFORE packages/evidence/src  -> `validation` = contracts
- apps/runtime-gateway/src BEFORE packages/detectors/src -> `trajectory` = gateway pkg
- apps/runtime-gateway/src BEFORE apps/worker/src         -> `config` = gateway

A proper workspace packaging decision (namespaced imports; hyphenated app dirs;
the contracts/evidence validation.py overlap) remains a shared item with
Developer B - see the handoff.
"""
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parent
_ORDER = (
    "apps/runtime-gateway/src",
    "packages/policy/src",
    "packages/detectors/src",
    "packages/aegis/src",
    "packages/attack-graph/src",
    "packages/contracts/src",
    "packages/evidence/src",
    "packages/domain/src",
    "apps/worker/src",
)
sys.path[:0] = [str(_ROOT / p) for p in _ORDER]
