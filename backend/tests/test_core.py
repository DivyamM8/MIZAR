from datetime import UTC, datetime, timedelta, timezone

import pytest

from mizar.core import ids
from mizar.core.timeutil import from_utc_storage, to_utc_storage

SHA = "ab" * 32


def test_event_id_is_deterministic_and_locator_order_independent() -> None:
    a = ids.event_id("CASE-1", "SF-1", SHA, {"kind": "line", "line": 7, "byte_offset": 100})
    b = ids.event_id("CASE-1", "SF-1", SHA.upper(), {"byte_offset": 100, "line": 7, "kind": "line"})
    assert a == b


def test_event_id_differs_per_case_source_file_content_and_record() -> None:
    line7 = {"kind": "line", "line": 7}
    base = ids.event_id("CASE-1", "SF-1", SHA, line7)
    assert ids.event_id("CASE-2", "SF-1", SHA, line7) != base
    assert ids.event_id("CASE-1", "SF-2", SHA, line7) != base
    assert ids.event_id("CASE-1", "SF-1", "cd" * 32, line7) != base
    assert ids.event_id("CASE-1", "SF-1", SHA, {"kind": "line", "line": 8}) != base


def test_prefixed_ids() -> None:
    assert ids.new_case_id().startswith("CASE-")
    assert ids.new_run_id().startswith("RUN-")
    assert ids.new_source_file_id().startswith("SF-")
    assert ids.finding_id("RUN-X", 3) == "RUN-X-F0003"
    with pytest.raises(ValueError):
        ids.finding_id("RUN-X", 0)


def test_utc_storage_round_trip_and_ordering() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    local = datetime(2026, 10, 29, 12, 0, 0, 123456, tzinfo=ist)
    text = to_utc_storage(local)
    assert text == "2026-10-29T06:30:00.123456Z"
    assert from_utc_storage(text) == local
    earlier = to_utc_storage(datetime(2026, 1, 2, tzinfo=UTC))
    assert earlier < text


def test_naive_datetime_is_refused() -> None:
    with pytest.raises(ValueError, match="naive"):
        to_utc_storage(datetime(2026, 10, 29, 12, 0, 0))


def test_event_schema_doc_is_current() -> None:
    from pathlib import Path

    from mizar.events.schema_docs import render

    doc = Path(__file__).resolve().parents[2] / "docs" / "event-schema.md"
    assert doc.read_text() == render(), (
        "run: python -m mizar.events.schema_docs > docs/event-schema.md"
    )
