from foundation import create_app


def test_p0_openapi_is_versioned_and_complete():
    schema = create_app('host=127.0.0.1 port=1 dbname=openapi',policy_signing_key='x'*32,
                        approval_signing_key='y'*32,evidence_signing_key='z'*32).openapi()
    required = {'/v1/organizations/{resource_id}','/v1/workspaces/{resource_id}',
        '/v1/environments/{resource_id}','/v1/identities/{identity_id}',
        '/v1/memberships/{membership_id}','/v1/assets/{asset_id}',
        '/v1/tool-capabilities/{capability_record_id}','/v1/approval-requests',
        '/v1/findings/{finding_id}','/v1/policies/{policy_id}',
        '/v1/evidence/uploads','/v1/evidence','/v1/audit','/v1/audit/verify'}
    required |= {'/v1/platform/limits','/v1/platform/usage','/v1/integrations',
                 '/v1/integrations/{integration_id}','/v1/integrations/{integration_id}/test',
                 '/v1/reports','/v1/analytics/runtime-summary'}
    required |= {'/scim/v2/Users','/scim/v2/Users/{identity_id}'}
    required |= {'/v1/sso/oidc-mappings','/v1/sso/oidc-mappings/{mapping_id}',
                 '/v1/report-schedules','/v1/report-schedules/{schedule_id}','/v1/billing/usage'}
    required |= {'/v1/campaigns','/v1/campaigns/{campaign_id}',
                 '/v1/campaigns/{campaign_id}/runs','/v1/campaigns/{campaign_id}/status',
                 '/v1/regression-cases'}
    required |= {'/v1/regression-cases/{case_id}/runs'}
    assert required <= set(schema['paths'])
    assert schema['info']['version'] == '1.0.0'
