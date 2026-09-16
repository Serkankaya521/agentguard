"""L2 cache client (Redis in production).

Redis HA is a platform (Developer B) concern. The runtime depends only on this
interface. InMemoryL2 is the dev/test adapter; RedisL2 is the production adapter,
guarded so a missing `redis` package degrades gracefully rather than crashing the
hot path (master arch 30.13 - bounded failure).
"""
from __future__ import annotations

import time
from typing import Any, Optional, Protocol


class L2Cache(Protocol):
    def get(self, key: str) -> tuple[Any, bool]: ...
    def set(self, key: str, value: Any, ttl_s: Optional[float] = None) -> None: ...
    def invalidate(self, key: str) -> None: ...
    def available(self) -> bool: ...


class InMemoryL2:
    """Deterministic in-process L2 for tests and single-node dev."""

    def __init__(self, default_ttl_s: float = 60.0) -> None:
        self._ttl = default_ttl_s
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> tuple[Any, bool]:
        item = self._data.get(key)
        if item is None:
            return None, False
        expiry, value = item
        if expiry != 0.0 and time.monotonic() > expiry:
            self._data.pop(key, None)
            return None, False
        return value, True

    def set(self, key: str, value: Any, ttl_s: Optional[float] = None) -> None:
        ttl = self._ttl if ttl_s is None else ttl_s
        expiry = 0.0 if ttl <= 0 else time.monotonic() + ttl
        self._data[key] = (expiry, value)

    def invalidate(self, key: str) -> None:
        self._data.pop(key, None)

    def available(self) -> bool:
        return True


class RedisL2:
    """Production adapter (guarded import). Falls back to unavailable if redis is
    missing or the server is unreachable, so the hot path never hard-fails here."""

    def __init__(self, url: str = "redis://localhost:6379/0", timeout_s: float = 0.05) -> None:
        self._ok = False
        self._client = None
        try:  # pragma: no cover - depends on optional dependency/environment
            import redis  # type: ignore
            self._client = redis.Redis.from_url(
                url, socket_timeout=timeout_s, socket_connect_timeout=timeout_s)
            self._client.ping()
            self._ok = True
        except Exception:
            self._ok = False

    def available(self) -> bool:
        return self._ok

    def get(self, key: str) -> tuple[Any, bool]:  # pragma: no cover - infra
        if not self._ok:
            return None, False
        try:
            raw = self._client.get(key)
            return (raw, True) if raw is not None else (None, False)
        except Exception:
            return None, False

    def set(self, key: str, value: Any, ttl_s: Optional[float] = None) -> None:  # pragma: no cover
        if not self._ok:
            return
        try:
            self._client.set(key, value, ex=int(ttl_s) if ttl_s else None)
        except Exception:
            pass

    def invalidate(self, key: str) -> None:  # pragma: no cover - infra
        if self._ok:
            try:
                self._client.delete(key)
            except Exception:
                pass
