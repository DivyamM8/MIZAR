"""JSON and CSV exports (DESIGN.md §13.2)."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import IO, Any

from sqlalchemy import Connection

from mizar.events.service import read_raw_record, with_parse_constants
from mizar.evidence.store import EvidenceStore
from mizar.reporting.data import ReportData, iter_case_events, iter_linked_events
from mizar.reporting.text import csv_cell
from mizar.versions import EVENT_SCHEMA_VERSION, MIZAR_VERSION

# The layout of report.json. MAJOR = breaking change, MINOR = new field.
EXPORT_FORMAT_VERSION = "1.0.0"
Progress = Callable[[str], None]

FINDING_CSV_COLUMNS = (
    "finding_id",
    "rule_id",
    "rule_version",
    "title",
    "severity",
    "confidence",
    "evidence_strength",
    "status",
    "first_observed_utc",
    "last_observed_utc",
    "event_count",
    "evidence_events_linked",
    "attack_techniques",
    "hostname",
    "username",
    "source_ip",
    "destination_ip",
    "source_files",
    "related_finding_ids",
    "description",
    "interpretation",
    "severity_rationale",
    "confidence_rationale",
    "analyst_notes",
    "updated_by",
    "updated_at",
)
EVENT_CSV_COLUMNS = (
    "event_id",
    "timestamp_utc",
    "timestamp_original",
    "timezone_assumption",
    "timestamp_precision",
    "source_file_id",
    "source_file",
    "source_type",
    "parser_name",
    "record_index",
    "hostname",
    "username",
    "user_domain",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "event_category",
    "event_type",
    "event_outcome",
    "event_code",
    "process_name",
    "process_id",
    "session_id",
    "message",
    "parsing_status",
    "record_hash",
    "finding_ids",
)
SOURCE_FILE_CSV_COLUMNS = (
    "source_file_id",
    "sequence",
    "filename",
    "original_filename",
    "archive_member_path",
    "parent_file_id",
    "size_bytes",
    "sha256",
    "ingestion_time",
    "status",
    "format",
    "parser_name",
    "parser_version",
    "parse_status",
    "records_total",
    "records_partial",
    "records_unparsed",
    "timezone_hint",
    "year_hint",
    "integrity_status",
    "verified_at",
    "still_present",
)


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return value.hex()
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _dumps(value: Any) -> str:
    return json.dumps(value, default=_default, ensure_ascii=False, sort_keys=True)


def _header(data: ReportData, export_id: str) -> dict[str, Any]:
    run = data.run
    case = data.case
    return {
        "export_format": "mizar.report",
        "export_format_version": EXPORT_FORMAT_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "generator": {"name": "MIZAR", "version": MIZAR_VERSION},
        "export_id": export_id,
        "generated_at": data.generated_at,
        "options": data.options,
        "case": {
            key: case[key]
            for key in ("case_id", "name", "reference", "analyst_name", "description", "created_at")
        },
        "run": {
            key: run[key]
            for key in (
                "run_id",
                "status",
                "triggered_by",
                "created_at",
                "started_at",
                "finished_at",
                "manifest_sha256",
                "inputs_fingerprint",
                "results",
                "manifest",
            )
        },
        "changed_since_run": data.changed_since_run,
        "summary": {
            "findings_in_run": data.run_counts,
            "findings_included": len(data.findings),
            "findings_excluded": data.excluded,
            "events_total": data.events_total,
            "events_without_reliable_time": data.events_unplaced,
            "first_event_utc": data.span[0],
            "last_event_utc": data.span[1],
            "timezone_assumptions": data.timezone_assumptions,
        },
        "source_files": data.source_files,
    }


def _finding_record(data: ReportData, finding: dict[str, Any]) -> dict[str, Any]:
    record = {k: v for k, v in finding.items() if k != "evidence"}
    record["evidence"] = [
        {"event_id": eid, "role": role, "present": eid in data.present}
        for eid, role in finding["evidence"]
    ]
    return record


def write_json(
    out: IO[str],
    conn: Connection,
    store: EvidenceStore,
    data: ReportData,
    export_id: str,
    progress: Progress,
) -> dict[str, int]:
    """One JSON document, written piece by piece so large cases are never held in memory."""
    header = _header(data, export_id)
    out.write("{\n")
    for key, value in header.items():
        out.write(f"{json.dumps(key)}: {_dumps(value)},\n")

    out.write('"findings": [')
    for index, finding in enumerate(data.findings):
        out.write(("," if index else "") + "\n" + _dumps(_finding_record(data, finding)))
    out.write("\n],\n")

    progress("Writing referenced events")
    out.write('"events": [')
    written = 0
    batch: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal written
        for event in with_parse_constants(conn, batch):
            record = {**event, "raw_record": read_raw_record(conn, store, event)}
            out.write(("," if written else "") + "\n" + _dumps(record))
            written += 1
        batch.clear()

    for event in iter_linked_events(conn, data):
        batch.append(event)
        if len(batch) == 500:
            flush()
    flush()
    out.write("\n]")
    if data.options["all_events"]:
        out.write(
            ',\n"all_events": {"file": "events.ndjson", "order": '
            '"timestamp_utc (no reliable time last), source_file_id, record_index"}'
        )
    out.write("\n}\n")
    return {"findings": len(data.findings), "events": written}


def write_ndjson(out: IO[str], conn: Connection, data: ReportData, progress: Progress) -> int:
    count = 0
    batch: list[dict[str, Any]] = []

    def flush() -> None:
        for event in with_parse_constants(conn, batch):
            out.write(_dumps(event) + "\n")
        batch.clear()

    for event in iter_case_events(conn, data):
        batch.append(event)
        count += 1
        if len(batch) == 2000:
            flush()
            if count % 100_000 == 0:
                progress(f"{count} events written")
    flush()
    return count


def _csv_text(columns: Iterable[str], rows: Iterable[dict[str, Any]]) -> Iterator[str]:
    """CSV lines, every value neutralized against formula injection."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    columns = list(columns)
    writer.writerow(columns)
    yield buffer.getvalue()
    for row in rows:
        buffer.seek(0)
        buffer.truncate()
        writer.writerow([csv_cell(row.get(c)) for c in columns])
        yield buffer.getvalue()


def _finding_rows(data: ReportData) -> Iterator[dict[str, Any]]:
    for finding in data.findings:
        entities = finding["entities"]
        yield {
            **finding,
            **{k: entities.get(k) for k in ("hostname", "username", "source_ip", "destination_ip")},
            "evidence_events_linked": len(finding["evidence"]),
            "source_files": [f"{f['filename']} ({f['sha256']})" for f in finding["source_files"]],
        }


def _event_rows(data: ReportData, events: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    names = {f["source_file_id"]: f["filename"] for f in data.source_files}
    linked: dict[str, list[str]] = {}
    for finding in data.findings:
        for event_id, _ in finding["evidence"]:
            linked.setdefault(event_id, []).append(finding["finding_id"])
    for event in events:
        yield {
            **event,
            "source_file": names.get(event["source_file_id"]),
            "finding_ids": sorted(set(linked.get(event["event_id"], []))),
        }


def _member(name: str) -> zipfile.ZipInfo:
    # A fixed timestamp keeps the archive bytes reproducible.
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _write_member(
    archive: zipfile.ZipFile, name: str, lines: Iterable[str], encoding: str = "utf-8"
) -> None:
    with (
        archive.open(_member(name), "w", force_zip64=True) as member,
        io.TextIOWrapper(member, encoding=encoding, newline="") as text,
    ):
        for line in lines:
            text.write(line)


def write_csv_bundle(
    path: Path, conn: Connection, data: ReportData, export_id: str, progress: Progress
) -> dict[str, int]:
    """A ZIP with findings.csv, events.csv, source_files.csv and export.json."""
    events: Iterable[dict[str, Any]]
    if data.options["all_events"]:
        events = iter_case_events(conn, data)
    else:
        events = iter_linked_events(conn, data)
    counts = {"findings": len(data.findings), "events": 0}

    def counted(rows: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for row in rows:
            counts["events"] += 1
            if counts["events"] % 100_000 == 0:
                progress(f"{counts['events']} events written")
            yield row

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        _write_member(archive, "export.json", [_dumps(_header(data, export_id)) + "\n"])
        # UTF-8 with a byte order mark: spreadsheet programs otherwise guess a legacy encoding.
        _write_member(
            archive,
            "findings.csv",
            _csv_text(FINDING_CSV_COLUMNS, _finding_rows(data)),
            "utf-8-sig",
        )
        _write_member(
            archive,
            "events.csv",
            _csv_text(EVENT_CSV_COLUMNS, _event_rows(data, counted(events))),
            "utf-8-sig",
        )
        _write_member(
            archive,
            "source_files.csv",
            _csv_text(SOURCE_FILE_CSV_COLUMNS, data.source_files),
            "utf-8-sig",
        )
    return counts


def write_json_bundle(
    path: Path,
    conn: Connection,
    store: EvidenceStore,
    data: ReportData,
    export_id: str,
    progress: Progress,
) -> dict[str, int]:
    """report.json, or a ZIP with report.json and events.ndjson when all events are wanted."""
    if not data.options["all_events"]:
        with path.open("w", encoding="utf-8") as out:
            return write_json(out, conn, store, data, export_id, progress)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        with (
            archive.open(_member("report.json"), "w", force_zip64=True) as member,
            io.TextIOWrapper(member, encoding="utf-8") as text,
        ):
            counts = write_json(text, conn, store, data, export_id, progress)
        progress("Writing all events")
        with (
            archive.open(_member("events.ndjson"), "w", force_zip64=True) as member,
            io.TextIOWrapper(member, encoding="utf-8") as text,
        ):
            counts["all_events"] = write_ndjson(text, conn, data, progress)
    return counts
