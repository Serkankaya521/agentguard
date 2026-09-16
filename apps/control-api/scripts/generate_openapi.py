"""Generate the versioned Control API OpenAPI artifact without connecting to DB."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/path) for path in (
    'apps/control-api/src','apps/runtime-gateway/src','packages/auth/src',
    'packages/observability/src','packages/contracts/src','packages/domain/src',
    'packages/policy/src','packages/evidence/src')]
from foundation import create_app

target = ROOT/'schemas/api/control_api.openapi.json'
document = create_app('host=127.0.0.1 port=1 dbname=openapi',
    policy_signing_key='x'*32,approval_signing_key='y'*32,
    evidence_signing_key='z'*32).openapi()
document['info']['x-agentguard-schema-version'] = '1.0.0'
target.write_text(json.dumps(document,indent=2,sort_keys=True)+'\n',encoding='utf-8')
print(target)
