"""Priority ordering reserves earlier service for runtime/evidence work."""
PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}


def priority_value(priority: str) -> int:
    try:
        return PRIORITY_ORDER[priority]
    except KeyError as exc:
        raise ValueError("unknown priority") from exc
