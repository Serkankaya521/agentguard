"""Trusted Kafka SecurityEvent to ClickHouse consumer with bounded batches."""
import json
import os

from kafka import KafkaConsumer
from analytics import ClickHouseAnalytics


def main():
    analytics=ClickHouseAnalytics(os.environ['CLICKHOUSE_ENDPOINT'],
        database=os.environ.get('CLICKHOUSE_DATABASE','agentguard'),
        user=os.environ.get('CLICKHOUSE_USER','agentguard'),password=os.environ['CLICKHOUSE_PASSWORD'])
    consumer=KafkaConsumer(os.environ.get('SECURITY_EVENT_TOPIC','security.events'),
        bootstrap_servers=os.environ['KAFKA_BOOTSTRAP_SERVERS'].split(','),
        group_id='agentguard-clickhouse-v1',enable_auto_commit=False,auto_offset_reset='earliest',
        max_poll_records=100,max_partition_fetch_bytes=1_048_576,
        value_deserializer=lambda value:json.loads(value))
    for record in consumer:
        headers=dict(record.headers or ())
        tenant=(headers.get('tenant_id') or b'').decode()
        if not tenant:
            continue
        analytics.insert_security_event(tenant,record.value)
        consumer.commit()

if __name__=='__main__':
    main()
