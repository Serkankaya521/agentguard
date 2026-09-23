"""Trusted Kafka SecurityEvent to ClickHouse consumer with bounded batches."""
import json
import os

from kafka import KafkaConsumer,KafkaProducer
from analytics import ClickHouseAnalytics
from validation import validate


def main():
    analytics=ClickHouseAnalytics(os.environ['CLICKHOUSE_ENDPOINT'],
        database=os.environ.get('CLICKHOUSE_DATABASE','agentguard'),
        user=os.environ.get('CLICKHOUSE_USER','agentguard'),password=os.environ['CLICKHOUSE_PASSWORD'])
    consumer=KafkaConsumer(os.environ.get('SECURITY_EVENT_TOPIC','security.events'),
        bootstrap_servers=os.environ['KAFKA_BOOTSTRAP_SERVERS'].split(','),
        group_id='agentguard-clickhouse-v1',enable_auto_commit=False,auto_offset_reset='earliest',
        max_poll_records=100,max_partition_fetch_bytes=1_048_576)
    dlq=KafkaProducer(bootstrap_servers=os.environ['KAFKA_BOOTSTRAP_SERVERS'].split(','),
                      acks='all',enable_idempotence=True)
    for record in consumer:
        try:
            headers=dict(record.headers or ())
            tenant=(headers.get('tenant_id') or b'').decode()
            if not tenant:raise ValueError('TENANT_HEADER_MISSING')
            value=json.loads(record.value)
            if validate(value,'security_event') or value.get('tenant',{}).get('tenant_id')!=tenant:
                raise ValueError('SECURITY_EVENT_INVALID')
        except Exception as exc:
            payload=json.dumps({'source_topic':record.topic,'partition':record.partition,
                'offset':record.offset,'error_code':type(exc).__name__,
                'value_sha256':__import__('hashlib').sha256(record.value).hexdigest()},
                separators=(',',':')).encode()
            dlq.send(os.environ.get('SECURITY_EVENT_DLQ_TOPIC','security.events.dlq'),
                     key=str(record.partition).encode(),value=payload,
                     headers=[('source_offset',str(record.offset).encode())]).get(timeout=3)
        else:
            # Transport failures remain uncommitted and are retried by Kafka.
            analytics.insert_security_event(tenant,value)
        # A poison message is durably represented in the DLQ before advancing.
        consumer.commit()

if __name__=='__main__':
    main()
