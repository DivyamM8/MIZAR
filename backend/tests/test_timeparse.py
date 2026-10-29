from datetime import UTC, datetime

import pytest

from mizar.parsers import timeparse


def test_explicit_offsets() -> None:
    stamp = timeparse.parse_iso("2026-10-29T12:00:01.1234567+05:30", None)
    assert stamp.utc == datetime(2026, 10, 29, 6, 30, 1, 123456, tzinfo=UTC)
    assert (stamp.assumption, stamp.precision) == ("explicit", "ns")
    assert timeparse.parse_iso("2026-10-29 12:00:01Z", None).utc == datetime(
        2026, 10, 29, 12, 0, 1, tzinfo=UTC
    )
    assert timeparse.parse_iso("2026-10-29T12:00:01-0800", None).utc == datetime(
        2026, 10, 29, 20, 0, 1, tzinfo=UTC
    )


def test_local_time_without_hint_has_no_utc() -> None:
    stamp = timeparse.parse_iso("2026-10-29T12:00:01", None)
    assert stamp.utc is None
    assert stamp.assumption == "none"
    assert stamp.original == "2026-10-29T12:00:01"
    assert "timezone_unknown" in stamp.warnings


def test_local_time_with_hint() -> None:
    stamp = timeparse.parse_iso("2026-07-01T12:00:00", "Europe/Berlin")
    assert stamp.utc == datetime(2026, 7, 1, 10, 0, tzinfo=UTC)
    assert stamp.assumption == "analyst_hint:Europe/Berlin"


@pytest.mark.parametrize(
    ("local", "warning"),
    [
        ("2026-11-01T01:30:00", "dst_ambiguous"),  # clocks fall back: happens twice
        ("2026-03-08T02:30:00", "dst_nonexistent"),  # clocks spring forward: never happens
    ],
)
def test_dst_edges_are_not_guessed(local: str, warning: str) -> None:
    stamp = timeparse.parse_iso(local, "America/New_York")
    assert stamp.utc is None
    assert stamp.warnings == (warning,)
    assert stamp.assumption == "analyst_hint:America/New_York"


def test_epoch_is_utc_by_definition() -> None:
    stamp = timeparse.from_epoch("1761739201.5", "1761739201.5", "ms")
    assert stamp.utc == datetime(2025, 10, 29, 12, 0, 1, 500000, tzinfo=UTC)
    assert stamp.assumption == "format_defined_utc"


@pytest.mark.parametrize("value", ["-5", "nan", "99999999999999", "abc"])
def test_invalid_epoch_is_unparsed(value: str) -> None:
    stamp = timeparse.from_epoch(value, value, "s")
    assert stamp.utc is None and "timestamp_unparsed" in stamp.warnings


@pytest.mark.parametrize("value", ["2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "yesterday"])
def test_invalid_dates_are_unparsed(value: str) -> None:
    stamp = timeparse.parse_iso(value, "UTC")
    assert stamp.utc is None
    assert stamp.original == value
    assert "timestamp_unparsed" in stamp.warnings
