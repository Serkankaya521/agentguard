"""Runtime-side active policy provider.

Holds the artifact store (source of truth for the active compiled policy) and
serves an optimized ruleset through the tiered cache, so the hot path reads a
precompiled, cached ruleset instead of parsing policy JSON per request
(master arch 30.6).
"""
from __future__ import annotations

from typing import Optional

from artifacts import CompiledPolicy, PolicyArtifactStore  # packages/policy/src
from compiler import default_compiled_policy  # packages/policy/src
from optimizer import OptimizedRuleset, optimize  # packages/policy/src

from cache import TieredCache, make_key  # apps/runtime-gateway/src/cache
from enums import CacheSource  # packages/domain/src


class ActivePolicyProvider:
    def __init__(self, store: Optional[PolicyArtifactStore] = None,
                 cache: Optional[TieredCache] = None) -> None:
        self._store = store or PolicyArtifactStore()
        if self._store.active() is None:
            self._store.publish(default_compiled_policy())
        self._cache = cache or TieredCache()

    @property
    def store(self) -> PolicyArtifactStore:
        return self._store

    @property
    def cache(self) -> TieredCache:
        return self._cache

    def get_active(self) -> tuple[OptimizedRuleset, CacheSource, CompiledPolicy]:
        compiled = self._store.active()
        assert compiled is not None
        key = make_key("policy", compiled.policy_version, compiled.policy_hash)
        ruleset, src = self._cache.get_or_compute(key, lambda: optimize(compiled))
        return ruleset, src, compiled
