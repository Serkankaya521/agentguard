"""OpenTelemetry bootstrap; exports no payload, token, secret or customer data."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Telemetry:
    tracer: object
    meter: object


def configure(service_name: str, endpoint: str | None = None) -> Telemetry:
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    resource = Resource.create({"service.name":service_name})
    tracer_provider = TracerProvider(resource=resource)
    meter_provider = MeterProvider(resource=resource)
    if endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)
    return Telemetry(trace.get_tracer(service_name), metrics.get_meter(service_name))
