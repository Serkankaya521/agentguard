"""Fail-fast platform configuration without secret repr/logging."""
from dataclasses import dataclass
import os


@dataclass(frozen=True, repr=False)
class Settings:
    database_url: str
    policy_signing_key: str
    approval_signing_key: str
    evidence_signing_key: str
    redis_url: str | None
    kafka_bootstrap_servers: str | None
    evidence_s3_endpoint: str | None
    evidence_s3_bucket: str | None
    otel_endpoint: str | None

    def __repr__(self):
        return "Settings(<redacted>)"

    @staticmethod
    def from_env():
        required = ("CONTROL_DATABASE_URL","POLICY_SIGNING_KEY",
                    "APPROVAL_SIGNING_KEY","EVIDENCE_SIGNING_KEY")
        missing = [name for name in required if len(os.environ.get(name,"")) < 32]
        if missing:
            raise RuntimeError("missing or weak required settings: " + ",".join(missing))
        endpoint, bucket = os.environ.get("EVIDENCE_S3_ENDPOINT"),os.environ.get("EVIDENCE_S3_BUCKET")
        if bool(endpoint) != bool(bucket):
            raise RuntimeError("EVIDENCE_S3_ENDPOINT and EVIDENCE_S3_BUCKET must be configured together")
        return Settings(os.environ["CONTROL_DATABASE_URL"],os.environ["POLICY_SIGNING_KEY"],
            os.environ["APPROVAL_SIGNING_KEY"],os.environ["EVIDENCE_SIGNING_KEY"],
            os.environ.get("REDIS_URL"),os.environ.get("KAFKA_BOOTSTRAP_SERVERS"),endpoint,bucket,
            os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
