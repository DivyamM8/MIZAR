"""Run a parser on bytes the way the parse job does, without a database."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from mizar.events.schema import event_json_schema
from mizar.ingest.detect import HEAD_BYTES, decode_head
from mizar.parsers import REGISTRY
from mizar.parsers.base import FileProblem, ParseContext
from mizar.parsers.pipeline import build_rows

_VALIDATOR = Draft202012Validator(event_json_schema(), format_checker=FormatChecker())
INGESTED = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def schema_view(event: dict[str, Any]) -> dict[str, Any]:
    """The event as JSON (datetimes as ISO strings), for schema validation."""
    return {
        key: value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value
        for key, value in event.items()
    }


def run(
    format_id: str,
    data: bytes | Path,
    tmp_path: Path,
    *,
    filename: str = "sample.log",
    timezone_hint: str | None = None,
    year_hint: int | None = None,
    encoding: str | None = None,
) -> tuple[list[dict[str, Any]], list[FileProblem], list[dict[str, Any] | None]]:
    """Returns (events, file problems, stored raw copies). Every event is schema-validated."""
    if isinstance(data, Path):
        path = data
        content = path.read_bytes()
    else:
        path = tmp_path / "blob"
        path.write_bytes(data)
        content = data
    if encoding is None:
        encoding = decode_head(content[:HEAD_BYTES])[1] or "utf-8"
    ctx = ParseContext(
        case_id="CASE-TEST",
        source_file_id="SF-TEST",
        sha256=hashlib.sha256(content).hexdigest(),
        filename=filename,
        blob_path=path,
        encoding=encoding,
        timezone_hint=timezone_hint,
        year_hint=year_hint,
    )
    parser = REGISTRY[format_id](ctx)
    events: list[dict[str, Any]] = []
    raws: list[dict[str, Any] | None] = []
    problems: list[FileProblem] = []
    with path.open("rb") as stream:
        for item in parser.records(stream):
            if isinstance(item, FileProblem):
                problems.append(item)
                continue
            rows = build_rows(parser, item, len(events), "PR-TEST", INGESTED)
            errors = sorted(_VALIDATOR.iter_errors(schema_view(rows.event)), key=str)
            assert not errors, [e.message for e in errors]
            events.append(rows.event)
            raws.append(rows.raw)
    return events, problems, raws
