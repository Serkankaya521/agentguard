"""Scheduled bounded report retention runner."""
import os
from tenant_ids import active_tenant_ids
from jobs.retention import ReportRetention
from object_store import S3ObjectStore

def main():
    tenants=active_tenant_ids(os.environ['CONTROL_DATABASE_URL'])
    store=S3ObjectStore(endpoint_url=os.environ['EVIDENCE_S3_ENDPOINT'],bucket=os.environ['EVIDENCE_S3_BUCKET'],
                        region=os.environ.get('EVIDENCE_S3_REGION','us-east-1'))
    retention=ReportRetention(os.environ['CONTROL_DATABASE_URL'],store)
    for tenant in tenants: retention.run_tenant(tenant)

if __name__=='__main__':main()
