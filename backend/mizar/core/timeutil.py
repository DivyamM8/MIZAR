"""Time helpers. MIZAR stores only timezone-aware UTC datetimes (DESIGN.md §4)."""

from __future__ import annotations

from datetime import UTC, datetime

UTC_STORAGE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_utc_storage(value: datetime) -> str:
    """Fixed-width ISO 8601 text that sorts chronologically. Naive datetimes are refused."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetime refused: timezone must be explicit")
    return value.astimezone(UTC).strftime(UTC_STORAGE_FORMAT)


def from_utc_storage(text: str) -> datetime:
    return datetime.strptime(text, UTC_STORAGE_FORMAT).replace(tzinfo=UTC)
