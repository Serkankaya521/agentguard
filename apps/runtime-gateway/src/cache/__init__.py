"""Tiered runtime cache: L1 (process) -> L2 (Redis) -> source (master arch 30.5)."""
from __future__ import annotations

from typing import Any, Callable, Optional

from enums import CacheSource  # packages/domain/src

from .l1 import L1Cache
from .l2 import InMemoryL2, L2Cache, RedisL2
from .invalidation import InvalidationConsumer


def make_key(namespace: str, version: str, *parts: str, tenant_id: Optional[str] = None) -> str:
    """Version-aware, tenant-safe cache key. Tenant is embedded so entries can
    never collide across tenants (task plan section 10)."""
    tenant = tenant_id or "-"
    return ":".join([namespace, version, tenant, *[str(p) for p in parts]])


class TieredCache:
    def __init__(self, l1: Optional[L1Cache] = None, l2: Optional[L2Cache] = None) -> None:
        self.l1 = l1 or L1Cache()
        self.l2 = l2  # optional; None -> single-tier

    def get_or_compute(
        self, key: str, compute: Callable[[], Any], ttl_s: Optional[float] = None
    ) -> tuple[Any, CacheSource]:
        value, hit = self.l1.get(key)
        if hit:
            return value, CacheSource.L1
        if self.l2 is not None and self.l2.available():
            v2, hit2 = self.l2.get(key)
            if hit2:
                self.l1.set(key, v2, ttl_s)
                return v2, CacheSource.L2
        value = compute()
        self.l1.set(key, value, ttl_s)
        if self.l2 is not None and self.l2.available():
            self.l2.set(key, value, ttl_s)
        return value, CacheSource.COMPUTED


__all__ = [
    "L1Cache", "L2Cache", "InMemoryL2", "RedisL2",
    "InvalidationConsumer", "TieredCache", "make_key",
]
