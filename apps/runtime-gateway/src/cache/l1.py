"""L1: process-local, bounded LRU + TTL cache with single-flight.

Normal requests should resolve from L1 (master arch 30.5). Bounded size and TTL
keep memory bounded; single-flight prevents cache stampede on a cold key.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Optional

_MISS = object()


class L1Cache:
    def __init__(self, max_size: int = 10_000, default_ttl_s: float = 30.0) -> None:
        self._max = max_size
        self._ttl = default_ttl_s
        self._data: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self._keylocks: dict[str, threading.Lock] = {}
        self.hits = 0
        self.misses = 0

    def _expired(self, expiry: float) -> bool:
        return expiry != 0.0 and time.monotonic() > expiry

    def get(self, key: str) -> tuple[Any, bool]:
        with self._lock:
            item = self._data.get(key, _MISS)
            if item is _MISS:
                self.misses += 1
                return None, False
            expiry, value = item
            if self._expired(expiry):
                self._data.pop(key, None)
                self.misses += 1
                return None, False
            self._data.move_to_end(key)
            self.hits += 1
            return value, True

    def set(self, key: str, value: Any, ttl_s: Optional[float] = None) -> None:
        ttl = self._ttl if ttl_s is None else ttl_s
        expiry = 0.0 if ttl <= 0 else time.monotonic() + ttl
        with self._lock:
            self._data[key] = (expiry, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)  # evict LRU

    def get_or_compute(self, key: str, compute: Callable[[], Any],
                       ttl_s: Optional[float] = None) -> tuple[Any, bool]:
        value, hit = self.get(key)
        if hit:
            return value, True
        # Single-flight: only one thread computes a given cold key.
        with self._lock:
            klock = self._keylocks.setdefault(key, threading.Lock())
        with klock:
            value, hit = self.get(key)  # re-check after acquiring
            if hit:
                return value, True
            value = compute()
            self.set(key, value, ttl_s)
            return value, False

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def invalidate_prefix(self, prefix: str) -> int:
        with self._lock:
            keys = [k for k in self._data if k.startswith(prefix)]
            for k in keys:
                self._data.pop(k, None)
            return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
