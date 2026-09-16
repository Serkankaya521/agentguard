"""Bounded ClickHouse analytics client; never used on the runtime hot path."""
import base64
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from validation import validate


class ClickHouseAnalytics:
    def __init__(self, endpoint: str, *, database: str = 'agentguard', user: str = 'agentguard',
                 password: str = '', timeout_s: float = 2.0, transport=None):
        if not endpoint.startswith(('http://','https://')) or not .1 <= timeout_s <= 10:
            raise ValueError('invalid ClickHouse configuration')
        self.endpoint,self.database,self.user,self.password=endpoint.rstrip('/'),database,user,password
        self.timeout_s,self.transport=timeout_s,transport or self._transport

    def _transport(self, query: str, body: bytes = b'', params: dict | None = None):
        url=self.endpoint+'/?'+urlencode({'database':self.database,'query':query,**(params or {})})
        token=base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        request=Request(url,data=body,method='POST',headers={'Authorization':'Basic '+token,
                        'Content-Type':'application/x-ndjson'})
        with urlopen(request,timeout=self.timeout_s) as response:
            return response.read(2_000_000)

    def insert_security_event(self, authenticated_tenant_id: str, event: dict):
        if validate(event,'security_event'):
            raise ValueError('SECURITY_EVENT_SCHEMA_INVALID')
        tenant=event['tenant']
        if tenant.get('tenant_id') != authenticated_tenant_id:
            raise ValueError('TENANT_CONTEXT_MISMATCH')
        row={'tenant_id':authenticated_tenant_id,'workspace_id':tenant['workspace_id'],
             'environment_id':tenant['environment_id'],'event_id':event['event_id'],
             'trace_id':event['trace_id'],'occurred_at':event['occurred_at'],'source':event['source'],
             'action_state':event['action_state'],'tool_id':event['tool_id'],
             'capability_id':event.get('declared_capability_id') or '',
             'payload_hash':event['payload_hash']}
        self.transport('INSERT INTO security_events FORMAT JSONEachRow',
                       (json.dumps(row,separators=(',',':'))+'\n').encode(),None)

    def runtime_summary(self, tenant_id: str, workspace_id: str, start, end):
        query=("SELECT action_state,tool_id,count() AS events FROM security_events "
               "WHERE tenant_id={tenant:UUID} AND workspace_id={workspace:UUID} "
               "AND occurred_at>={start:DateTime64(3)} AND occurred_at<{end:DateTime64(3)} "
               "GROUP BY action_state,tool_id ORDER BY events DESC LIMIT 100 FORMAT JSON")
        raw=self.transport(query,b'',{'param_tenant':tenant_id,'param_workspace':workspace_id,
                                      'param_start':start.isoformat(),'param_end':end.isoformat()})
        return json.loads(raw or b'{"data":[]}').get('data',[])
