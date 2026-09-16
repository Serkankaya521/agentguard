"""Bounded-cardinality platform metrics."""


class PlatformMetrics:
    def __init__(self, meter):
        self.requests = meter.create_counter("control.requests")
        self.failures = meter.create_counter("control.failures")
        self.outbox = meter.create_up_down_counter("platform.outbox.depth")
        self.jobs = meter.create_up_down_counter("platform.jobs.depth")
        self.latency = meter.create_histogram("control.duration", unit="ms")

    @staticmethod
    def attributes(*, operation: str, status: str):
        # Never use tenant/user/resource IDs as metric labels.
        return {"operation":operation[:80],"status":status[:32]}
