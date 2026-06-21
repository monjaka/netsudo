"""Duration parsing and formatting."""

from __future__ import annotations

import re


_TOKEN = re.compile(r"(?P<num>\d+)(?P<unit>s|m|h|d)")
_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 24 * 60 * 60,
}


def parse_duration(value: str | int) -> int:
    """Parse a duration like 30m, 1h, 1h30m, or seconds as an int."""
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("duration must be positive")
        return value

    raw = str(value).strip().lower()
    if raw.isdigit():
        seconds = int(raw)
        if seconds <= 0:
            raise ValueError("duration must be positive")
        return seconds

    pos = 0
    total = 0
    for match in _TOKEN.finditer(raw):
        if match.start() != pos:
            raise ValueError(f"invalid duration: {value}")
        pos = match.end()
        total += int(match.group("num")) * _UNIT_SECONDS[match.group("unit")]

    if pos != len(raw) or total <= 0:
        raise ValueError(f"invalid duration: {value}")
    return total


def format_duration(seconds: int) -> str:
    """Format seconds as a compact duration string."""
    if seconds < 0:
        seconds = 0
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return "".join(parts)
