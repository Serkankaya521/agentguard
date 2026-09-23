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
from urllib.parse import unquote, urldefrag, urljoin

from jsonschema import Draft202012Validator

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
    "policy": "policies/policy.schema.json",
    "compiled_policy": "policies/compiled_policy.schema.json",
    "cache_invalidation_event": "events/cache_invalidation_event.schema.json",
    "risk_profile": "risk/risk_profile.schema.json",
    "learning_event": "events/learning_event.schema.json",
    "evidence": "evidence/evidence.schema.json",
    "finding": "findings/finding.schema.json",
    "approval_request": "approvals/approval_request.schema.json",
    "approval_decision": "approvals/approval_decision.schema.json",
    "job_envelope": "queues/job_envelope.schema.json",
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
def _schemas_by_id() -> dict[str, dict]:
    return {s["$id"]: s for s in map(load_schema, CONTRACTS) if "$id" in s}


def _pointer(doc, fragment: str):
    node = doc
    for part in unquote(fragment).lstrip("/").split("/") if fragment else ():
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def bundle(schema: dict) -> dict:
    """Return a copy of `schema` with every $ref (local or cross-contract) inlined.

    security_event is validated on the runtime hot path. Resolving $ref through a
    resolver/registry on every call costs ~30us per request, and the registry API
    needs jsonschema>=4.18. Inlining once at load time leaves only plain keyword
    checks per call and works on any jsonschema 4.x.
    """
    by_id = _schemas_by_id()

    def resolve(node, base: str, doc: dict, seen: frozenset):
        if isinstance(node, list):
            return [resolve(v, base, doc, seen) for v in node]
        if not isinstance(node, dict):
            return node
        if "$ref" not in node:
            return {k: resolve(v, base, doc, seen) for k, v in node.items()}
        uri, fragment = urldefrag(urljoin(base, node["$ref"]))
        uri = uri or base  # a bare "#/..." ref points into the current document
        target_doc = doc if uri == base else by_id.get(uri)
        if target_doc is None:
            raise UnknownContract(node["$ref"])
        if (uri, fragment) in seen:
            raise ValueError(f"recursive $ref cannot be inlined: {node['$ref']}")
        inlined = resolve(_pointer(target_doc, fragment), uri, target_doc,
                          seen | {(uri, fragment)})
        if isinstance(inlined, dict):
            inlined = {k: v for k, v in inlined.items() if k not in ("$id", "$schema")}
        siblings = {k: resolve(v, base, doc, seen) for k, v in node.items() if k != "$ref"}
        return {"allOf": [inlined, siblings]} if siblings else inlined

    return resolve(schema, schema.get("$id", ""), schema, frozenset())


@functools.lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(bundle(load_schema(name)))


def validate(payload: dict, name: str) -> list[str]:
    """Return a list of human-readable errors; empty means valid."""
    validator = _validator(name)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


def is_valid(payload: dict, name: str) -> bool:
    return not validate(payload, name)
