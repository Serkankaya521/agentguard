"""Dependency-free local adapters for the AgentGuard security lab.

These adapters deliberately model only single-process development behavior. They
do not pretend to provide Redis HA, broker durability, S3 retention or ClickHouse
scale. Tenant IDs remain mandatory so prototype code exercises the same boundary.
"""
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
from threading import RLock
import time
from typing import Any


@dataclass(frozen=True)
class LocalSettings:
    profile: str = 'local-security-lab'
    tenant_id: str = 'agentguard-lab'
    workspace_id: str = 'security-research'
    queue_capacity: int = 1_000
    cache_capacity: int = 2_000
    sqlite_path: str = ':memory:'

    def __post_init__(self):
        if self.profile != 'local-security-lab':
            raise ValueError('local runtime is restricted to local-security-lab profile')
        if not self.tenant_id or not self.workspace_id:
            raise ValueError('tenant and workspace are required')
        if not 10 <= self.queue_capacity <= 100_000 or not 10 <= self.cache_capacity <= 100_000:
            raise ValueError('local adapter bounds are invalid')

    @classmethod
    def from_env(cls):
        return cls(profile=os.environ.get('AGENTGUARD_PROFILE','local-security-lab'),
                   tenant_id=os.environ.get('AGENTGUARD_LOCAL_TENANT','agentguard-lab'),
                   workspace_id=os.environ.get('AGENTGUARD_LOCAL_WORKSPACE','security-research'),
                   queue_capacity=int(os.environ.get('AGENTGUARD_LOCAL_QUEUE_CAPACITY','1000')),
                   cache_capacity=int(os.environ.get('AGENTGUARD_LOCAL_CACHE_CAPACITY','2000')),
                   sqlite_path=os.environ.get('AGENTGUARD_LOCAL_SQLITE',':memory:'))


class LocalCache:
    def __init__(self, capacity: int):
        self.capacity,self._data,self._lock=capacity,OrderedDict(),RLock()

    def set(self, tenant_id: str, key: str, value: Any, ttl_s: float = 60):
        if not tenant_id or not key or not 0 < ttl_s <= 86_400: raise ValueError('invalid cache entry')
        scoped=(tenant_id,key)
        with self._lock:
            self._data[scoped]=(time.monotonic()+ttl_s,value);self._data.move_to_end(scoped)
            while len(self._data)>self.capacity:self._data.popitem(last=False)

    def get(self, tenant_id: str, key: str):
        scoped=(tenant_id,key)
        with self._lock:
            item=self._data.get(scoped)
            if not item:return None
            if time.monotonic()>item[0]:self._data.pop(scoped,None);return None
            self._data.move_to_end(scoped);return item[1]

    def __len__(self): return len(self._data)


class LocalEventBus:
    def __init__(self, capacity: int):
        self.capacity,self._queue,self._dlq,self._seen=capacity,deque(),deque(maxlen=capacity),set()

    def publish(self, tenant_id: str, event: dict) -> bool:
        event_id=str(event.get('event_id',''))
        if not tenant_id or not event_id: raise ValueError('tenant_id and event_id required')
        dedupe=(tenant_id,event_id)
        if dedupe in self._seen:return False
        if len(self._queue)>=self.capacity:raise RuntimeError('LOCAL_QUEUE_CAPACITY_EXCEEDED')
        self._seen.add(dedupe);self._queue.append({'tenant_id':tenant_id,**event});return True

    def poll(self, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 1000:raise ValueError('invalid poll bound')
        return [self._queue.popleft() for _ in range(min(limit,len(self._queue)))]

    def reject(self,event:dict,error_code:str):self._dlq.append({**event,'error_code':error_code[:64]})
    def depth(self):return len(self._queue)
    def dlq_depth(self):return len(self._dlq)


class LocalObjectStore:
    def __init__(self):self._objects={}
    def put(self,tenant_id:str,key:str,content:bytes,media_type='application/json'):
        if not key.startswith(tenant_id+'/') or '..' in key.split('/'):raise ValueError('unsafe object key')
        digest=hashlib.sha256(content).hexdigest();self._objects[key]=(tenant_id,bytes(content),media_type,digest)
        return {'key':key,'size_bytes':len(content),'sha256':digest,'media_type':media_type}
    def get(self,tenant_id:str,key:str)->bytes:
        owner,content,_,_=self._objects[key]
        if owner!=tenant_id:raise ValueError('cross-tenant object access')
        return content
    def count(self):return len(self._objects)
    def inventory(self,tenant_id:str)->list[dict]:
        return [{'key':key,'media_type':value[2],'sha256':value[3],'size_bytes':len(value[1])}
                for key,value in self._objects.items() if value[0]==tenant_id]


class SQLiteAnalytics:
    def __init__(self,path=':memory:'):
        self._lock=RLock();self._db=sqlite3.connect(path,check_same_thread=False)
        self._db.execute('CREATE TABLE IF NOT EXISTS events(tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,kind TEXT NOT NULL,created_at TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant_id,event_id))')
    def record(self,tenant_id:str,event_id:str,kind:str,payload:dict)->bool:
        with self._lock:
            cursor=self._db.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)',(tenant_id,event_id,kind,datetime.now(timezone.utc).isoformat(),json.dumps(payload,separators=(',',':'),sort_keys=True)))
            self._db.commit();return cursor.rowcount==1
    def summary(self,tenant_id:str):
        with self._lock:
            return [{'kind':row[0],'events':row[1]} for row in self._db.execute('SELECT kind,count(*) FROM events WHERE tenant_id=? GROUP BY kind ORDER BY kind',(tenant_id,))]
    def recent(self,tenant_id:str,limit:int=50):
        if not 1<=limit<=200:raise ValueError('invalid analytics limit')
        with self._lock:
            return [{'event_id':row[0],'kind':row[1],'created_at':row[2]}
                    for row in self._db.execute('SELECT event_id,kind,created_at FROM events WHERE tenant_id=? ORDER BY created_at DESC LIMIT?',(tenant_id,limit))]


class PrototypeRuntime:
    def __init__(self,settings:LocalSettings=LocalSettings()):
        self.settings=settings
        self.cache=LocalCache(settings.cache_capacity)
        self.events=LocalEventBus(settings.queue_capacity)
        self.objects=LocalObjectStore()
        self.analytics=SQLiteAnalytics(settings.sqlite_path)

    def capture_campaign(self,result) -> dict:
        payload={'campaign_id':result.campaign_id,'target':result.target,'executed':result.executed,
                 'refused':result.refused,'killed':result.killed,'budget_exhausted':result.budget_exhausted,
                 'unauthorized':result.unauthorized,'observations':list(result.observations)}
        event_id='campaign:'+result.campaign_id+':'+hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()[:16]
        event={'event_id':event_id,'kind':'red_team.completed','payload':payload}
        self.events.publish(self.settings.tenant_id,event)
        self.analytics.record(self.settings.tenant_id,event_id,event['kind'],payload)
        content=(json.dumps(payload,indent=2,sort_keys=True)+'\n').encode()
        artifact=self.objects.put(self.settings.tenant_id,f'{self.settings.tenant_id}/evidence/{event_id}.json',content)
        self.cache.set(self.settings.tenant_id,'last_campaign',payload,ttl_s=3600)
        return artifact

    def status(self):
        return {'profile':self.settings.profile,'tenant_id':self.settings.tenant_id,
                'cache':'in-memory','event_bus':'in-memory bounded queue','object_store':'in-memory',
                'analytics':'sqlite '+self.settings.sqlite_path,'queue_depth':self.events.depth(),
                'dlq_depth':self.events.dlq_depth(),'objects':self.objects.count(),'cache_entries':len(self.cache)}
