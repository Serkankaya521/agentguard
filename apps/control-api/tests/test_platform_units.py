import logging

import fakeredis
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from abac import attributes_allow
from identity import Principal
from object_store import MemoryObjectStore, ObjectMetadata, validate_object_key
from platform_cache import ApprovalReplayGuard, RedisCache
from rbac import permits
from scim import parse_user
from sso import OIDCValidator
from analytics import ClickHouseAnalytics
from jobs.integrations import SafeWebhookSender,provider_payload


def test_rbac_abac_default_deny():
    principal = Principal('t','i','user',workspace_roles={'w':'editor'},
                          attributes={'environments':['test']})
    assert permits(principal,'asset.manage','w')
    assert not permits(principal,'identity.manage','w')
    assert attributes_allow(principal,environment_kind='test')
    assert not attributes_allow(principal,environment_kind='production')


def test_scim_rejects_tenant_injection():
    user = parse_user({'externalId':'e','userName':'u','active':True})
    assert user.external_id == 'e'
    with pytest.raises(ValueError):
        parse_user({'externalId':'e','userName':'u','tenant_id':'evil'})


def test_redis_tenant_keys_ttl_invalidation_and_storm_bound():
    client = fakeredis.FakeRedis()
    cache = RedisCache(client=client)
    cache.set_json('tenant-a','policy','active','1',{'v':1},ttl_s=60)
    cache.set_json('tenant-b','policy','active','1',{'v':2},ttl_s=60)
    assert cache.get_json('tenant-a','policy','active','1') == {'v':1}
    assert cache.invalidate_prefix('tenant-a','policy','active') == 1
    assert cache.get_json('tenant-b','policy','active','1') == {'v':2}
    for index in range(10100):
        cache.set_json('tenant-a','storm','active',str(index),{'v':index},ttl_s=60)
    deleted = cache.invalidate_prefix('tenant-a','storm','active')
    assert deleted <= 10000


def test_object_store_rejects_cross_tenant_and_metadata_mismatch():
    store = MemoryObjectStore()
    store.seed('t1','t1/evidence/x',ObjectMetadata(3,'a'*64,'text/plain'))
    assert store.head('t1','t1/evidence/x').size_bytes == 3
    with pytest.raises(ValueError): validate_object_key('t2','t1/evidence/x')
    with pytest.raises((KeyError,ValueError)): store.head('t2','t2/evidence/x')


def test_approval_nonce_is_atomic_across_instances():
    client = fakeredis.FakeRedis()
    first, second = ApprovalReplayGuard(client), ApprovalReplayGuard(client)
    assert first.consume('tenant-a','nonce123',ttl_s=60)
    assert not second.consume('tenant-a','nonce123',ttl_s=60)
    assert second.consume('tenant-b','nonce123',ttl_s=60)
    second.revoke('tenant-a','future-nonce',ttl_s=60)
    assert not first.consume('tenant-a','future-nonce',ttl_s=60)


def test_oidc_signature_issuer_and_audience_are_verified():
    private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public = private.public_key()
    class JWKS:
        def get_signing_key_from_jwt(self,token):
            return type('Key',(),{'key':public})()
    validator = OIDCValidator.__new__(OIDCValidator)
    validator.issuer,validator.audience,validator.algorithms,validator.jwks = 'https://issuer','agentguard',('RS256',),JWKS()
    import time
    claims = {'iss':'https://issuer','aud':'agentguard','sub':'user-1','iat':int(time.time()),'exp':int(time.time())+60}
    token = jwt.encode(claims,private,algorithm='RS256')
    assert validator.validate(token).subject == 'user-1'
    bad = jwt.encode({**claims,'aud':'other'},private,algorithm='RS256')
    with pytest.raises(jwt.InvalidAudienceError): validator.validate(bad)


def test_clickhouse_ingest_is_tenant_bound_and_query_is_parameterized():
    calls=[]
    def transport(query,body,params):
        calls.append((query,body,params))
        return b'{"data":[{"action_state":"blocked","tool_id":"shell","events":"2"}]}'
    client=ClickHouseAnalytics('https://clickhouse.invalid',transport=transport)
    tenant={'schema_version':'1.0.0','tenant_id':'tenant-a','workspace_id':'workspace-a',
            'environment_id':'environment-a','environment':'test','identity_id':'identity-a',
            'identity_type':'service'}
    event={'schema_version':'1.0.0','event_id':'event-a','trace_id':'trace-a',
           'occurred_at':'2026-09-16T00:00:00Z','source':'mcp','action_state':'blocked',
           'tenant':tenant,'tool_id':'shell','payload_hash':'a'*64}
    client.insert_security_event('tenant-a',event)
    assert b'"tenant_id":"tenant-a"' in calls[0][1]
    with pytest.raises(ValueError): client.insert_security_event('tenant-b',event)
    from datetime import datetime,timezone
    result=client.runtime_summary('tenant-a','workspace-a',datetime.now(timezone.utc),datetime.now(timezone.utc))
    assert result[0]['events']=='2' and calls[-1][2]['param_tenant']=='tenant-a'


def test_webhook_sender_fails_closed_before_network():
    sender=SafeWebhookSender(['hooks.example.com'])
    with pytest.raises(ValueError): sender('http://hooks.example.com/x',{},b'key')
    with pytest.raises(ValueError): sender('https://127.0.0.1/x',{},b'key')

def test_enterprise_connector_payloads_are_provider_specific():
    event={'event_type':'finding.confirmed','event_id':'e1'}
    assert provider_payload('slack',event,{})['text'].startswith('AgentGuard')
    assert provider_payload('jira',event,{'project_key':'AG'})['fields']['project']['key']=='AG'
    assert provider_payload('github',event,{})['event_type']=='agentguard_finding'
    with pytest.raises(ValueError):provider_payload('unknown',event,{})
