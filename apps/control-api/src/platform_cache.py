"""Tenant-safe Redis cache and bounded stampede protection."""
import json
import re
from contextlib import contextmanager

SAFE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


def cache_key(tenant_id: str, namespace: str, key: str, version: str) -> str:
    parts = (tenant_id, namespace, key, version)
    if not all(SAFE.fullmatch(str(part)) for part in parts):
        raise ValueError("unsafe cache key component")
    return "ag:" + ":".join(str(part) for part in parts)


class RedisCache:
    def __init__(self, url: str | None = None, *, socket_timeout: float = 0.05,
                 client=None):
        if client is None:
            import redis
            if not url:
                raise ValueError("redis URL required")
            client = redis.Redis.from_url(url, socket_timeout=socket_timeout,
                                          socket_connect_timeout=socket_timeout,
                                          health_check_interval=30)
        self.client = client

    def get_json(self, tenant_id, namespace, key, version):
        raw = self.client.get(cache_key(tenant_id,namespace,key,version))
        return None if raw is None else json.loads(raw)

    def set_json(self, tenant_id, namespace, key, version, value, *, ttl_s=300):
        if not 1 <= ttl_s <= 86400:
            raise ValueError("unbounded cache ttl")
        self.client.set(cache_key(tenant_id,namespace,key,version),
                        json.dumps(value,separators=(",",":"),sort_keys=True), ex=ttl_s)

    def invalidate_prefix(self, tenant_id, namespace, key):
        prefix = cache_key(tenant_id,namespace,key,"prefix").rsplit(':',1)[0] + ':'
        cursor, deleted = 0, 0
        while True:
            cursor, keys = self.client.scan(cursor=cursor,match=prefix+'*',count=100)
            if keys:
                deleted += self.client.unlink(*keys)
            if cursor == 0 or deleted >= 10000:
                break
        return deleted

    @contextmanager
    def stampede_lock(self, tenant_id, namespace, key, *, timeout_s=3):
        lock = self.client.lock(cache_key(tenant_id,namespace,key,"lock"), timeout=timeout_s,
                                blocking_timeout=min(timeout_s,0.2))
        acquired = lock.acquire()
        try:
            yield acquired
        finally:
            if acquired:
                lock.release()


class ApprovalReplayGuard:
    """Atomic cross-instance nonce consumption for Runtime Gateway integration."""
    def __init__(self, client):
        self.client = client

    def consume(self, tenant_id: str, nonce: str, *, ttl_s: int) -> bool:
        if not SAFE.fullmatch(nonce) or not 1 <= ttl_s <= 86400:
            raise ValueError("invalid approval nonce")
        key = cache_key(tenant_id,"approval","nonce-"+nonce,"1")
        return bool(self.client.set(key,"used",nx=True,ex=ttl_s))

    def revoke(self, tenant_id: str, nonce: str, *, ttl_s: int) -> None:
        if not SAFE.fullmatch(nonce) or not 1 <= ttl_s <= 86400:
            raise ValueError("invalid approval nonce")
        key = cache_key(tenant_id,"approval","nonce-"+nonce,"1")
        self.client.set(key,"revoked",ex=ttl_s)
