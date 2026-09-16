"""Deterministic local P3 adapter failure drill (no Docker/services required)."""
import json
import time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dashboard.local_runtime import LocalSettings,PrototypeRuntime

def run():
    rt=PrototypeRuntime(LocalSettings(queue_capacity=10,cache_capacity=10))
    tenant=rt.settings.tenant_id;checks={}
    rt.cache.set(tenant,'short','value',ttl_s=.001);time.sleep(.03)
    checks['cache_expiry']=rt.cache.get(tenant,'short') is None
    first=rt.events.publish(tenant,{'event_id':'duplicate','kind':'test','payload':{}})
    second=rt.events.publish(tenant,{'event_id':'duplicate','kind':'test','payload':{}})
    checks['event_dedup']=first and not second
    event=rt.events.poll(1)[0];rt.events.reject(event,'POISON_MESSAGE');checks['dlq_isolation']=rt.events.dlq_depth()==1
    artifact=rt.objects.put(tenant,f'{tenant}/drill/object.json',b'{}')
    try:rt.objects.get('other',artifact['key']);checks['object_tenant_isolation']=False
    except ValueError:checks['object_tenant_isolation']=True
    checks['analytics_idempotency']=rt.analytics.record(tenant,'a1','test',{}) and not rt.analytics.record(tenant,'a1','test',{})
    return {'passed':all(checks.values()),'checks':checks,'status':rt.status()}
if __name__=='__main__':
    result=run();print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['passed'] else 1)
