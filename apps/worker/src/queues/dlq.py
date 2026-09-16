"""Poison-message classification without persisting raw exception text."""


def error_code(exc: Exception) -> str:
    return type(exc).__name__[:120]


def should_dead_letter(attempt: int, max_attempts: int) -> bool:
    return attempt >= max_attempts
