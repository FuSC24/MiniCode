"""Shared helpers for tool implementations."""


def _clamp_timeout(value, default: int, hi: int) -> int:
    """Coerce a possibly-None / negative / oversized timeout into a sane int.

    Models sometimes pass `null` or wild values for `timeout`. Without this,
    `subprocess.run(timeout=None)` would block forever and a huge value
    would let a runaway shell hang the agent indefinitely.
    """
    try:
        v = int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
    if v <= 0:
        return default
    return min(v, hi)
