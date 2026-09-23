"""Platform outbox process. Run separately from request-serving workers."""
import os
import signal
import time
import psycopg

from event_backbone import KafkaProducerAdapter, OutboxPublisher


def main():
    dsn=os.environ['CONTROL_DATABASE_URL']
    publisher = OutboxPublisher(dsn,
        KafkaProducerAdapter(os.environ['KAFKA_BOOTSTRAP_SERVERS']),batch_size=100)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM,stop)
    while running:
        with psycopg.connect(dsn) as conn:
            tenants=tuple(row[0] for row in conn.execute('SELECT * FROM platform.active_tenant_ids()'))
        work = sum(publisher.deliver_once(tenant).published for tenant in tenants)
        if not work:
            time.sleep(.25)


if __name__ == '__main__':
    main()
