"""Idempotent, bounded outbound integration delivery."""
import hashlib
import hmac
import json
import os
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import psycopg
from psycopg.rows import dict_row

def provider_payload(kind:str,event:dict,configuration:dict)->dict:
    summary=f"AgentGuard {event.get('event_type','event')} ({event.get('event_id','unknown')})"
    base={'agentguard_event':event,'tenant_safe':True}
    if kind=='slack':return {'text':summary,'blocks':[]}
    if kind=='teams':return {'type':'message','text':summary}
    if kind=='jira':return {'fields':{'project':{'key':configuration.get('project_key','SEC')},'summary':summary,'description':json.dumps(base,separators=(',',':')),'issuetype':{'name':'Task'}}}
    if kind=='servicenow':return {'short_description':summary,'description':json.dumps(base,separators=(',',':'))}
    if kind in ('siem','webhook'):return base
    if kind in ('github','gitlab'):return {'event_type':'agentguard_finding','client_payload':base}
    if kind=='email':return {'subject':summary,'text':json.dumps(base,separators=(',',':'))}
    raise ValueError('INTEGRATION_TYPE_UNSUPPORTED')


class EnvironmentSecretResolver:
    def __call__(self, reference: str | None) -> bytes:
        if not reference:
            return b''
        if not reference.startswith('env://'):
            raise ValueError('SECRET_PROVIDER_UNAVAILABLE')
        name=reference[6:]
        if not name or name not in os.environ:
            raise ValueError('SECRET_NOT_FOUND')
        return os.environ[name].encode()


class SafeWebhookSender:
    def __init__(self, allowed_hosts, *, timeout_s: float = 3.0):
        self.allowed_hosts=frozenset(allowed_hosts)
        if not .1 <= timeout_s <= 10:
            raise ValueError('bounded timeout required')
        self.timeout_s=timeout_s

    def __call__(self, endpoint: str, payload: dict, secret: bytes) -> int:
        parsed=urlsplit(endpoint)
        if parsed.scheme!='https' or parsed.hostname not in self.allowed_hosts or parsed.username:
            raise ValueError('DESTINATION_DENIED')
        body=json.dumps(payload,separators=(',',':'),sort_keys=True).encode()
        signature=hmac.new(secret,body,hashlib.sha256).hexdigest() if secret else ''
        request=Request(endpoint,data=body,method='POST',headers={
            'Content-Type':'application/json','User-Agent':'AgentGuard-Integration/1.0',
            'X-AgentGuard-Signature':'sha256='+signature,
        })
        with urlopen(request,timeout=self.timeout_s) as response:
            response.read(4096)
            if not 200 <= response.status < 300:
                raise RuntimeError('DESTINATION_REJECTED')
            return response.status


class IntegrationDelivery:
    def __init__(self, dsn: str, sender, secret_resolver):
        self.dsn,self.sender,self.secret_resolver=dsn,sender,secret_resolver

    def __call__(self,envelope: dict):
        tenant_id,delivery_id=envelope['tenant_id'],envelope['payload']['delivery_id']
        with psycopg.connect(self.dsn,row_factory=dict_row,
                             options='-c statement_timeout=10000 -c lock_timeout=1000') as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant_id,))
            row=conn.execute(
                'SELECT d.*,i.endpoint,i.secret_ref,i.enabled,i.integration_type,i.configuration FROM platform.integration_deliveries d '
                'JOIN platform.integrations i ON i.tenant_id=d.tenant_id AND i.id=d.integration_id '
                'WHERE d.id=%s FOR UPDATE OF d',(delivery_id,),
            ).fetchone()
            if not row:
                raise ValueError('DELIVERY_NOT_FOUND')
            if row['status']=='completed':
                return {'status':'completed','response_code':row['response_code']}
            if not row['enabled'] or not row['endpoint']:
                raise ValueError('INTEGRATION_DISABLED')
            conn.execute("UPDATE platform.integration_deliveries SET status='running',attempts=attempts+1,last_error_code=NULL WHERE id=%s",(delivery_id,))
            try:
                outbound=provider_payload(row['integration_type'],dict(row['payload']),dict(row['configuration']))
                response_code=self.sender(row['endpoint'],outbound,self.secret_resolver(row['secret_ref']))
                conn.execute("UPDATE platform.integration_deliveries SET status='completed',response_code=%s,delivered_at=clock_timestamp() WHERE id=%s",
                             (response_code,delivery_id))
                return {'status':'completed','response_code':response_code}
            except Exception as exc:
                conn.execute("UPDATE platform.integration_deliveries SET status='failed',last_error_code=%s WHERE id=%s",
                             (type(exc).__name__.upper()[:64],delivery_id))
                raise
