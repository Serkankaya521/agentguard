from dataclasses import dataclass


@dataclass(frozen=True)
class LagState:
    pending: int
    oldest_age_seconds: float
    alert: bool


def evaluate(*, pending: int, oldest_age_seconds: float,
             max_pending: int = 10000, max_age_seconds: float = 60) -> LagState:
    if pending < 0 or oldest_age_seconds < 0:
        raise ValueError("negative lag")
    return LagState(pending,oldest_age_seconds,
                    pending >= max_pending or oldest_age_seconds >= max_age_seconds)
