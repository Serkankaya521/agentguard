"""Shared-contract validation against the versioned JSON Schemas in schemas/.

`schemas/` is the integration boundary and source of truth (AGENTS.md #6).
Generated/dataclass types live near consumers, but every cross-component payload
is validated here at the trust boundary.
"""
from __future__ import annotations

import functools
import json
import pathlib
from typing import Optional

import jsonschema
from jsonschema import Draft202012Validator
from jsonschema.validators import RefResolver

# repo_root/packages/contracts/src/validation.py -> parents[3] == repo root
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SCHEMAS_DIR = _REPO_ROOT / "schemas"

# Logical contract name -> schema file (relative to schemas/).
CONTRACTS: dict[str, str] = {
    "tenant_context": "tenancy/tenant_context.schema.json",
    "tool_capability": "capabilities/tool_capability.schema.json",
    "security_event": "events/security_event.schema.json",
    "policy_decision": "policies/policy_decision.schema.json",
    "runtime_decision": "runtime/runtime_decision.schema.json",
}


class UnknownContract(KeyError):
    pass


def schemas_dir() -> pathlib.Path:
    return _SCHEMAS_DIR


@functools.lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    if name not in CONTRACTS:
        raise UnknownContract(name)
    path = _SCHEMAS_DIR / CONTRACTS[name]
    return json.loads(path.read_text(encoding="utf-8"))


def schema_version(name: str) -> Optional[str]:
    return load_schema(name).get("version")


@functools.lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    # Resolve cross-schema $ref (e.g. security_event -> tenant_context) from disk.
    store = {}
    for logical, rel in CONTRACTS.items():
        s = load_schema(logical)
        if "$id" in s:
            store[s["$id"]] = s
    resolver = RefResolver(base_uri=schema.get("$id", ""), referrer=schema, store=store)
    return Draft202012Validator(schema, resolver=resolver)


def validate(payload: dict, name: str) -> list[str]:
    """Return a list of human-readable errors; empty means valid."""
    validator = _validator(name)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


def is_valid(payload: dict, name: str) -> bool:
    return not validate(payload, name)
