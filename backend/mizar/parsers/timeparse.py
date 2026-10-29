"""Timestamp interpretation under the timezone policy (DESIGN.md §4).

timestamp_utc is set only when the record carries an offset, the format
defines UTC, or the analyst supplied a timezone. Ambiguous or nonexistent
local times (DST) are never resolved by guessing.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from mizar.parsers.base import Timestamp

_ISO = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?\s*(?P<tz>Z|z|UTC|[+-]\d{2}(?::?\d{2})?)?$"
)
_MAX_EPOCH = 32503680000  # year 3000


def precision_for(fraction_digits: int) -> str:
    if fraction_digits == 0:
        return "s"
    if fraction_digits <= 3:
        return "ms"
    if fraction_digits <= 6:
        return "us"
    return "ns"


def _micro(fraction: str | None) -> int:
    if not fraction:
        return 0
    return int(fraction[:6].ljust(6, "0"))


def unparsed(original: str | None) -> Timestamp:
    return Timestamp(original, None, None, "none", ("timestamp_unparsed",))


def explicit(original: str, aware: datetime, precision: str) -> Timestamp:
    return Timestamp(original, aware.astimezone(UTC), precision, "explicit")


def from_epoch(original: str, seconds: str | int | float | Decimal, precision: str) -> Timestamp:
    """Epoch seconds are UTC by definition."""
    try:
        value = Decimal(str(seconds))
    except InvalidOperation:
        return unparsed(original)
    if not value.is_finite() or value < 0 or value > _MAX_EPOCH:
        return unparsed(original)
    whole = int(value)
    micros = int((value - whole) * 1_000_000)
    utc = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=whole, microseconds=micros)
    return Timestamp(original, utc, precision, "format_defined_utc")


def from_local(
    original: str, naive: datetime, precision: str, timezone_hint: str | None
) -> Timestamp:
    """A wall-clock time without offset: needs the analyst's timezone hint."""
    if timezone_hint is None:
        return Timestamp(original, None, precision, "none", ("timezone_unknown",))
    zone = ZoneInfo(timezone_hint)
    first = naive.replace(tzinfo=zone, fold=0)
    second = naive.replace(tzinfo=zone, fold=1)
    assumption = f"analyst_hint:{timezone_hint}"
    if first.utcoffset() != second.utcoffset():
        round_trip = first.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
        warning = "dst_nonexistent" if round_trip != naive else "dst_ambiguous"
        return Timestamp(original, None, precision, assumption, (warning,))
    return Timestamp(original, first.astimezone(UTC), precision, assumption)


def parse_iso(original: str, timezone_hint: str | None) -> Timestamp:
    """ISO 8601 / RFC 3339, with or without offset, any fraction length."""
    match = _ISO.match(original.strip())
    if not match:
        return unparsed(original)
    try:
        naive = datetime.fromisoformat(
            f"{match['date']}T{match['h']}:{match['m']}:{match['s']}"
        ).replace(microsecond=_micro(match["frac"]))
    except ValueError:
        return unparsed(original)
    precision = precision_for(len(match["frac"] or ""))
    tz = match["tz"]
    if tz is None:
        return from_local(original, naive, precision, timezone_hint)
    if tz in ("Z", "z", "UTC"):
        return explicit(original, naive.replace(tzinfo=UTC), precision)
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    hours, minutes = int(digits[:2]), int(digits[2:4] or 0)
    if hours > 23 or minutes > 59:
        return unparsed(original)
    offset = timezone(sign * timedelta(hours=hours, minutes=minutes))
    return explicit(original, naive.replace(tzinfo=offset), precision)


def parse_with_formats(
    original: str, formats: tuple[str, ...], timezone_hint: str | None
) -> Timestamp:
    """strptime formats; %z formats yield explicit times, others need the hint."""
    text = original.strip()
    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        fraction = len(text.rsplit(".", 1)[1].split()[0]) if "%f" in fmt else 0
        precision = precision_for(min(fraction, 6))
        if parsed.tzinfo is not None:
            return explicit(original, parsed, precision)
        return from_local(original, parsed, precision, timezone_hint)
    return unparsed(original)
