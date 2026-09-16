"""Admission rule for bounded per-tenant queues."""
from dataclasses import dataclass


@dataclass(frozen=True)
class QueueLimits:
    per_tenant: int = 1000
    global_total: int = 10000

    def __post_init__(self):
        if not 1 <= self.per_tenant <= self.global_total <= 1_000_000:
            raise ValueError("invalid queue limits")


def admitted(*, tenant_depth: int, global_depth: int, priority: str,
             limits: QueueLimits) -> bool:
    if tenant_depth < limits.per_tenant and global_depth < limits.global_total:
        return True
    # Preserve critical evidence/runtime work within a small emergency margin.
    return priority in ("P1", "P2") and global_depth < limits.global_total + 100
