CREATE DATABASE IF NOT EXISTS agentguard;
CREATE TABLE IF NOT EXISTS agentguard.security_events (
  tenant_id UUID,
  workspace_id UUID,
  environment_id UUID,
  event_id String,
  trace_id String,
  occurred_at DateTime64(3,'UTC'),
  source LowCardinality(String),
  action_state LowCardinality(String),
  tool_id String,
  capability_id String,
  payload_hash String,
  ingested_at DateTime64(3,'UTC') DEFAULT now64(3)
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY (tenant_id,toYYYYMM(occurred_at))
ORDER BY (tenant_id,workspace_id,occurred_at,event_id)
TTL occurred_at + INTERVAL 400 DAY DELETE;
