"""Platform job worker with per-tenant round-robin fairness."""
import os
import signal
import time

from queues.repository import JobRepository


HANDLERS = {}


def register(job_type, handler):
    if job_type in HANDLERS:
        raise ValueError('duplicate job handler')
    HANDLERS[job_type] = handler


def main(*,include_defaults=True):
    tenants = tuple(filter(None,os.environ.get('PLATFORM_TENANT_IDS','').split(',')))
    if not tenants:
        raise RuntimeError('PLATFORM_TENANT_IDS is required')
    repo = JobRepository(os.environ['CONTROL_DATABASE_URL'],max_batch=16)
    if include_defaults and 'report.generate' not in HANDLERS:
        from jobs.reporting import ReportGenerator
        from object_store import S3ObjectStore
        store=S3ObjectStore(endpoint_url=os.environ['EVIDENCE_S3_ENDPOINT'],
                            bucket=os.environ['EVIDENCE_S3_BUCKET'],
                            region=os.environ.get('EVIDENCE_S3_REGION','us-east-1'))
        register('report.generate',ReportGenerator(os.environ['CONTROL_DATABASE_URL'],store))
    if include_defaults and 'integration.deliver' not in HANDLERS:
        from jobs.integrations import EnvironmentSecretResolver,IntegrationDelivery,SafeWebhookSender
        allowed=tuple(filter(None,os.environ.get('INTEGRATION_ALLOWED_HOSTS','').split(',')))
        register('integration.deliver',IntegrationDelivery(
            os.environ['CONTROL_DATABASE_URL'],SafeWebhookSender(allowed),EnvironmentSecretResolver()))
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM,stop)
    while running:
        claimed = 0
        for tenant in tenants:
            for job in repo.claim(tenant,job_types=tuple(HANDLERS)):
                claimed += 1
                try:
                    handler = HANDLERS[job['job_type']]
                    handler(job['envelope'])
                except Exception as exc:
                    repo.fail(tenant,job['id'],exc)
                else:
                    repo.complete(tenant,job['id'])
        if not claimed:
            time.sleep(.25)


if __name__ == '__main__':
    main()
