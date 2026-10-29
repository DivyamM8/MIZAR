"""Parse job: run the file's parser and store normalized events (DESIGN.md §6.1 step 6).

Re-parsing replaces the file's events (same parser + same input gives the same
event IDs); earlier parse results are kept, marked not current. A file-level
error keeps every event produced before it. Cancellation removes the partial
events of the interrupted parse.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime
from operator import itemgetter
from typing import Any

from sqlalchemy import Engine, delete, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import new_parse_result_id
from mizar.core.timeutil import to_utc_storage, utc_now
from mizar.db.tables import events, parse_results, raw_records
from mizar.events.dedup import needs_rebuild, rebuild_duplicate_groups
from mizar.evidence import service as evidence
from mizar.jobs.worker import JobCancelled, JobContext, WorkerStopping
from mizar.parsers import REGISTRY
from mizar.parsers.base import FileParseError, FileProblem, ParseContext
from mizar.parsers.pipeline import build_rows
from mizar.versions import EVENT_SCHEMA_VERSION

log = logging.getLogger(__name__)

PARSE_JOB = "parse_file"
BATCH_SIZE = 5000
_MAX_PROBLEMS_KEPT = 200


class _Stats:
    def __init__(self) -> None:
        self.total = 0
        self.by_status: Counter[str] = Counter()
        self.warnings: Counter[str] = Counter()
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.problems: list[dict[str, Any]] = []
        self.problem_counts: Counter[str] = Counter()

    def add_event(self, event: dict[str, Any]) -> None:
        self.total += 1
        self.by_status[event["parsing_status"]] += 1
        self.warnings.update(event["parse_warnings"])
        stamp = event["timestamp_utc"]
        if stamp is not None:
            self.first = stamp if self.first is None else min(self.first, stamp)
            self.last = stamp if self.last is None else max(self.last, stamp)

    def add_problem(self, problem: FileProblem) -> None:
        self.problem_counts[problem.code] += 1
        if len(self.problems) < _MAX_PROBLEMS_KEPT:
            self.problems.append(
                {"code": problem.code, "message": problem.message, "details": problem.details}
            )

    def columns(self) -> dict[str, Any]:
        return {
            "records_total": self.total,
            "records_parsed": self.by_status["parsed"],
            "records_partial": self.by_status["partial"],
            "records_unparsed": self.by_status["unparsed"],
            "warnings_by_code": dict(self.warnings),
            "file_problems": {"counts": dict(self.problem_counts), "samples": self.problems},
            "first_timestamp_utc": self.first,
            "last_timestamp_utc": self.last,
        }

    @property
    def has_warnings(self) -> bool:
        return bool(self.problem_counts or self.by_status["partial"] or self.by_status["unparsed"])


def queue_parse(conn: Any, case_id: str, source_file_id: str) -> str:
    from mizar.jobs import queue

    return queue.enqueue(conn, PARSE_JOB, {"source_file_id": source_file_id}, case_id)


def _start(
    engine: Engine, row: dict[str, Any], format_id: str, parser_cls: Any
) -> tuple[str, datetime]:
    """Create the parse result. Its started_at is the ingestion_time of every event."""
    parse_result_id = new_parse_result_id()
    started = utc_now()
    file_id = row["source_file_id"]
    with engine.begin() as conn:
        # A parse interrupted by a crash leaves a 'running' result behind.
        conn.execute(
            update(parse_results)
            .where(parse_results.c.source_file_id == file_id, parse_results.c.status == "running")
            .values(
                status="failed",
                finished_at=utc_now(),
                error_code=ErrorCode.JOB_CRASHED.value,
                error_message="The parse was interrupted.",
            )
        )
        conn.execute(delete(events).where(events.c.source_file_id == file_id))
        conn.execute(
            update(parse_results)
            .where(parse_results.c.source_file_id == file_id)
            .values(is_current=False)
        )
        conn.execute(
            insert(parse_results).values(
                parse_result_id=parse_result_id,
                case_id=row["case_id"],
                source_file_id=file_id,
                is_current=True,
                format_id=format_id,
                parser_name=parser_cls.name,
                parser_version=parser_cls.version,
                schema_version=EVENT_SCHEMA_VERSION,
                timezone_hint=row["timezone_hint"],
                year_hint=row["year_hint"],
                status="running",
                started_at=started,
                warnings_by_code={},
                file_problems={},
            )
        )
    return parse_result_id, started


# Bulk inserts bypass SQLAlchemy's per-row compile and type layers (the hot path);
# values are converted here exactly as the column types would store them.
_EVENT_COLUMNS = tuple(column.name for column in events.columns)
# Column names come from the table definition; all values are bound parameters.
_INSERT_EVENTS = (
    f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) "  # noqa: S608
    f"VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)})"
)
_RAW_COLUMNS = tuple(column.name for column in raw_records.columns)
_INSERT_RAW = (
    f"INSERT INTO raw_records ({', '.join(_RAW_COLUMNS)}) "  # noqa: S608
    f"VALUES ({', '.join('?' for _ in _RAW_COLUMNS)})"
)


def _check_storage_columns() -> None:
    from mizar.events.schema import FIELDS

    stored_elsewhere = {"schema_version", "parser_version", "ingestion_time"}
    if set(_EVENT_COLUMNS) != set(FIELDS) - stored_elsewhere:
        raise RuntimeError("events table and event schema fields disagree")


_check_storage_columns()


_EVENT_GETTER = itemgetter(*_EVENT_COLUMNS)
_LOCATOR_POSITION = _EVENT_COLUMNS.index("original_record_reference")
_EXTRA_POSITION = _EVENT_COLUMNS.index("extra")
_WARNINGS_POSITION = _EVENT_COLUMNS.index("parse_warnings")
_TIMESTAMP_POSITION = _EVENT_COLUMNS.index("timestamp_utc")


def _storage_row(rows: Any) -> tuple[Any, ...]:
    """Column values as the JSON and UTCDateTime column types would store them."""
    values = list(_EVENT_GETTER(rows.event))
    values[_LOCATOR_POSITION] = rows.locator_json
    values[_EXTRA_POSITION] = json.dumps(values[_EXTRA_POSITION])
    values[_WARNINGS_POSITION] = json.dumps(values[_WARNINGS_POSITION])
    stamp = values[_TIMESTAMP_POSITION]
    if stamp is not None:
        values[_TIMESTAMP_POSITION] = to_utc_storage(stamp)
    return tuple(values)


def _flush(engine: Engine, batch: list[Any]) -> None:
    if not batch:
        return
    event_rows = [_storage_row(rows) for rows in batch]
    raw_rows = [tuple(rows.raw[column] for column in _RAW_COLUMNS) for rows in batch if rows.raw]
    with engine.begin() as conn:
        cursor = conn.connection.driver_connection.cursor()  # type: ignore[union-attr]
        try:
            cursor.executemany(_INSERT_EVENTS, event_rows)
            if raw_rows:
                cursor.executemany(_INSERT_RAW, raw_rows)
        finally:
            cursor.close()
    batch.clear()


def _finish(engine: Engine, parse_result_id: str, status: str, stats: _Stats, **error: Any) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(parse_results)
            .where(parse_results.c.parse_result_id == parse_result_id)
            .values(status=status, finished_at=utc_now(), **stats.columns(), **error)
        )


def parse_file_job(ctx: JobContext) -> dict[str, Any]:
    deps = ctx.deps
    file_id: str = ctx.payload["source_file_id"]
    with deps.engine.connect() as conn:
        row = evidence.get_source_file_conn(conn, file_id)
    if row["status"] != "ready":
        return {"source_file_id": file_id, "skipped": f"file status is {row['status']}"}
    format_id = row["format_override"] or row["detected_format"]
    parser_cls = REGISTRY.get(format_id)
    if parser_cls is None:
        raise MizarError(ErrorCode.FORMAT_UNDETECTED, f"No parser for format {format_id!r}.")

    parser = parser_cls(
        ParseContext(
            case_id=row["case_id"],
            source_file_id=file_id,
            sha256=row["blob_sha256"],
            filename=row["original_filename"],
            blob_path=deps.store.blob_path(row["blob_sha256"]),
            encoding=row["encoding"],
            timezone_hint=row["timezone_hint"],
            year_hint=row["year_hint"],
        )
    )
    parse_result_id, ingestion_time = _start(deps.engine, row, format_id, parser_cls)
    stats = _Stats()
    batch: list[Any] = []
    size = max(row["size_bytes"], 1)
    stream = deps.store.open(row["blob_sha256"])
    try:
        for item in parser.records(stream):
            if isinstance(item, FileProblem):
                stats.add_problem(item)
                continue
            rows = build_rows(parser, item, stats.total, parse_result_id, ingestion_time)
            stats.add_event(rows.event)
            batch.append(rows)
            if len(batch) >= BATCH_SIZE:
                _flush(deps.engine, batch)
                position = stream.tell() if not stream.closed else 0
                ctx.progress(min(position / size, 0.99), f"{stats.total} records")
        _flush(deps.engine, batch)
    except FileParseError as exc:
        _flush(deps.engine, batch)
        _finish(
            deps.engine,
            parse_result_id,
            "failed",
            stats,
            error_code=exc.code,
            error_message=exc.message,
        )
        log.warning(
            "parse failed: %s", exc.code, extra={"job_id": ctx.job_id, "case_id": row["case_id"]}
        )
        return _summary(file_id, parse_result_id, "failed", stats)
    except (JobCancelled, WorkerStopping):
        with deps.engine.begin() as conn:
            conn.execute(delete(events).where(events.c.parse_result_id == parse_result_id))
        _finish(
            deps.engine,
            parse_result_id,
            "cancelled",
            _Stats(),
            error_code=ErrorCode.JOB_CANCELLED.value,
            error_message="The parse was stopped before it finished; its events were removed.",
        )
        raise
    except Exception as exc:
        code = exc.code if isinstance(exc, MizarError) else ErrorCode.INTERNAL_ERROR
        _finish(
            deps.engine,
            parse_result_id,
            "failed",
            stats,
            error_code=code.value,
            error_message=(
                f"Parsing stopped unexpectedly. See the application log for job {ctx.job_id}."
            ),
        )
        raise
    finally:
        stream.close()

    status = "succeeded_with_warnings" if stats.has_warnings else "succeeded"
    _finish(deps.engine, parse_result_id, status, stats)
    if needs_rebuild(deps.engine, row["case_id"], file_id):
        rebuild_duplicate_groups(deps.engine, row["case_id"])
    _refresh_planner_statistics(deps.engine)
    return _summary(file_id, parse_result_id, status, stats)


def _refresh_planner_statistics(engine: Engine) -> None:
    """Sampled ANALYZE so the query planner picks selective indexes (bounded cost)."""
    with engine.connect() as conn:
        driver = conn.connection.driver_connection
        driver.execute("PRAGMA analysis_limit=1000")  # type: ignore[union-attr]
        driver.execute("PRAGMA optimize=0x10002")  # type: ignore[union-attr]


def _summary(file_id: str, parse_result_id: str, status: str, stats: _Stats) -> dict[str, Any]:
    return {
        "source_file_id": file_id,
        "parse_result_id": parse_result_id,
        "status": status,
        "records_total": stats.total,
        "file_problems": dict(stats.problem_counts),
    }


def current_parse_results(engine: Engine, case_id: str) -> dict[str, dict[str, Any]]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(parse_results).where(
                parse_results.c.case_id == case_id, parse_results.c.is_current.is_(True)
            )
        ).mappings()
        return {row["source_file_id"]: dict(row) for row in rows}
