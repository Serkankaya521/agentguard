"""Canonical serialization, content hashing, and redaction.

- canonical JSON is deterministic (sorted keys, tight separators) so hashes and
  golden tests are reproducible;
- content_hash lets the hot path carry a payload *reference* instead of a large
  inline payload (master arch 30.15);
- redact keeps PII/secrets out of logs, metadata, and evidence.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from enum import Enum
from typing import Any, Iterable

SENSITIVE_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "api_key", "apikey", "private_key", "client_secret",
    "cookie", "set-cookie", "ssn", "credit_card", "card_number", "cvv",
})
REDACTED = "[REDACTED]"


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/tuples into JSON-native values."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return str(obj)


def canonical_json(obj: Any) -> str:
    return json.dumps(
        to_jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def content_hash(obj: Any) -> str:
    digest = hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def redact(obj: Any, sensitive_keys: Iterable[str] = SENSITIVE_KEYS) -> Any:
    keys = {k.lower() for k in sensitive_keys}
    return _redact(to_jsonable(obj), keys)


def _redact(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        return {
            k: (REDACTED if k.lower() in keys else _redact(v, keys))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(v, keys) for v in obj]
    return obj
