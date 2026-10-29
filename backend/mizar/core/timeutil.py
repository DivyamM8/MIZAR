"""Time helpers. MIZAR stores only timezone-aware UTC datetimes (DESIGN.md §4)."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC_STORAGE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_utc_storage(value: datetime) -> str:
    """Fixed-width ISO 8601 text that sorts chronologically. Naive datetimes are refused."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetime refused: timezone must be explicit")
    # isoformat is several times faster than strftime and yields the same fixed width.
    return value.astimezone(UTC).replace(tzinfo=None).isoformat(timespec="microseconds") + "Z"


def from_utc_storage(text: str) -> datetime:
    return datetime.strptime(text, UTC_STORAGE_FORMAT).replace(tzinfo=UTC)


def validate_timezone_name(name: str) -> str:
    """Return name if it is a known IANA timezone, else raise ValueError."""
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown IANA timezone {name!r}") from exc
    return name
