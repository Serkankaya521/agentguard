"""Platform outbox process. Run separately from request-serving workers."""
import os
import signal
import time

from event_backbone import KafkaProducerAdapter, OutboxPublisher


def main():
    tenants = tuple(filter(None,os.environ.get('PLATFORM_TENANT_IDS','').split(',')))
    if not tenants:
        raise RuntimeError('PLATFORM_TENANT_IDS is required for fair tenant scheduling')
    publisher = OutboxPublisher(os.environ['CONTROL_DATABASE_URL'],
        KafkaProducerAdapter(os.environ['KAFKA_BOOTSTRAP_SERVERS']),batch_size=100)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM,stop)
    while running:
        work = sum(publisher.deliver_once(tenant).published for tenant in tenants)
        if not work:
            time.sleep(.25)


if __name__ == '__main__':
    main()
