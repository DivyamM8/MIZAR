"""Unified timeline (DESIGN.md §10.3).

Placed events (reliable UTC time) are paged with a keyset cursor on
(timestamp_utc, source_file_id, record_index), which the events index covers, so
any page costs the same. Events without a reliable UTC time live in a separate
"unplaced" lane in file order; they are never interleaved by guesswork.
"""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Engine,
    and_,
    func,
    literal,
    literal_column,
    select,
    text,
    tuple_,
)

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.timeutil import from_utc_storage, to_utc_storage
from mizar.db.tables import analysis_runs, finding_events, findings, source_files
from mizar.db.tables import events as events_table
from mizar.detection.rules import SEVERITIES
from mizar.events.service import EventFilter, _conditions
from mizar.evidence.service import require_case

MAX_PAGE = 500
MAX_BUCKETS = 500
_NICE_BUCKETS = (
    1,
    5,
    10,
    30,
    60,
    300,
    600,
    900,
    1800,
    3600,
    7200,
    10800,
    21600,
    43200,
    86400,
    172800,
    604800,
    2592000,
)
_MESSAGE_PREVIEW = 500
_COLUMNS = [
    events_table.c.event_id,
    events_table.c.timestamp_utc,
    events_table.c.timestamp_original,
    events_table.c.timezone_assumption,
    events_table.c.source_file_id,
    events_table.c.record_index,
    events_table.c.source_type,
    events_table.c.hostname,
    events_table.c.username,
    events_table.c.source_ip,
    events_table.c.destination_ip,
    events_table.c.destination_port,
    events_table.c.event_category,
    events_table.c.event_type,
    events_table.c.event_outcome,
    events_table.c.event_code,
    events_table.c.session_id,
    events_table.c.parsing_status,
    events_table.c.message,
]


@dataclass(frozen=True)
class FindingFilter:
    run_id: str | None = None
    min_severity: str | None = None
    finding_id: str | None = None


def _bad_cursor() -> MizarError:
    return MizarError(ErrorCode.VALIDATION_ERROR, "The cursor is invalid or from another lane.")


def encode_cursor(lane: str, row: dict[str, Any]) -> str:
    key: list[Any] = [row["source_file_id"], row["record_index"]]
    if lane == "placed":
        key.insert(0, to_utc_storage(row["timestamp_utc"]))
    raw = json.dumps([lane, *key], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(lane: str, cursor: str) -> tuple[Any, ...]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise _bad_cursor() from exc
    if not isinstance(value, list) or not value or value[0] != lane:
        raise _bad_cursor()
    key = value[1:]
    try:
        if lane == "placed":
            stamp, file_id, index = key
            return (from_utc_storage(stamp), str(file_id), int(index))
        file_id, index = key
        return (str(file_id), int(index))
    except (TypeError, ValueError) as exc:
        raise _bad_cursor() from exc


def latest_run_id(engine: Engine, case_id: str) -> str | None:
    with engine.connect() as conn:
        return conn.execute(
            select(analysis_runs.c.run_id)
            .where(
                analysis_runs.c.case_id == case_id,
                analysis_runs.c.status.in_(("succeeded", "succeeded_with_errors")),
            )
            .order_by(analysis_runs.c.created_at.desc())
            .limit(1)
        ).scalar()


def _finding_condition(flt: FindingFilter) -> Any:
    """Events that are evidence of findings matching the filter (one run)."""
    linked = select(finding_events.c.event_id).join(
        findings, findings.c.finding_id == finding_events.c.finding_id
    )
    if flt.finding_id:
        linked = linked.where(findings.c.finding_id == flt.finding_id)
    else:
        linked = linked.where(findings.c.run_id == flt.run_id)
        if flt.min_severity:
            allowed = SEVERITIES[SEVERITIES.index(flt.min_severity) :]
            linked = linked.where(findings.c.severity.in_(allowed))
    return events_table.c.event_id.in_(linked)


def _where(case_id: str, flt: EventFilter, findings_flt: FindingFilter | None) -> list[Any]:
    conditions = _conditions(case_id, flt)
    if findings_flt is not None and (findings_flt.min_severity or findings_flt.finding_id):
        conditions.append(_finding_condition(findings_flt))
    return conditions


def page(
    engine: Engine,
    case_id: str,
    flt: EventFilter,
    *,
    lane: str = "placed",
    after: str | None = None,
    before: str | None = None,
    limit: int = 100,
    findings_flt: FindingFilter | None = None,
) -> dict[str, Any]:
    if lane not in ("placed", "unplaced"):
        raise MizarError(ErrorCode.VALIDATION_ERROR, "lane must be 'placed' or 'unplaced'.")
    if after and before:
        raise MizarError(ErrorCode.VALIDATION_ERROR, "Use either 'after' or 'before', not both.")
    limit = min(max(limit, 1), MAX_PAGE)
    stamp = events_table.c.timestamp_utc
    key_columns = (
        [stamp, events_table.c.source_file_id, events_table.c.record_index]
        if lane == "placed"
        else [events_table.c.source_file_id, events_table.c.record_index]
    )
    conditions = _where(case_id, flt, findings_flt)
    conditions.append(stamp.is_not(None) if lane == "placed" else stamp.is_(None))
    backwards = before is not None
    if after or before:
        cursor = decode_cursor(lane, after or before or "")
        # Bind through the column types: timestamps must compare as stored text.
        bound = tuple_(*(literal(v, c.type) for v, c in zip(cursor, key_columns, strict=True)))
        key = tuple_(*key_columns)
        conditions.append(key < bound if backwards else key > bound)
    order = [c.desc() for c in key_columns] if backwards else key_columns
    with engine.connect() as conn:
        require_case(conn, case_id)
        rows = [
            dict(r)
            for r in conn.execute(
                select(*_COLUMNS).where(and_(*conditions)).order_by(*order).limit(limit + 1)
            ).mappings()
        ]
        more = len(rows) > limit
        rows = rows[:limit]
        if backwards:
            rows.reverse()
        names = dict(
            conn.execute(
                select(
                    source_files.c.source_file_id,
                    func.coalesce(
                        source_files.c.archive_member_path, source_files.c.original_filename
                    ),
                ).where(source_files.c.case_id == case_id)
            ).all()
        )
        run_id = findings_flt.run_id if findings_flt else None
        markers = _markers(conn, run_id, [r["event_id"] for r in rows])
    for row in rows:
        row["source_filename"] = names.get(row["source_file_id"])
        row["findings"] = markers.get(row["event_id"], [])
        message = row["message"]
        if message is not None and len(message) > _MESSAGE_PREVIEW:
            row["message"] = message[:_MESSAGE_PREVIEW]
            row["message_truncated"] = True
        else:
            row["message_truncated"] = False
    has_before = bool(rows) and (more if backwards else after is not None)
    has_after = bool(rows) and (before is not None if backwards else more)
    return {
        "lane": lane,
        "run_id": run_id,
        "items": rows,
        "next_cursor": encode_cursor(lane, rows[-1]) if has_after else None,
        "prev_cursor": encode_cursor(lane, rows[0]) if has_before else None,
    }


def _markers(
    conn: Any, run_id: str | None, event_ids: list[str]
) -> dict[str, list[dict[str, str]]]:
    if not run_id or not event_ids:
        return {}
    found: dict[str, list[dict[str, str]]] = {}
    rows = conn.execute(
        select(
            finding_events.c.event_id,
            findings.c.finding_id,
            findings.c.rule_id,
            findings.c.severity,
            finding_events.c.role,
        )
        .join(findings, findings.c.finding_id == finding_events.c.finding_id)
        .where(findings.c.run_id == run_id, finding_events.c.event_id.in_(event_ids))
        .order_by(findings.c.finding_id)
    )
    for event_id, finding_id, rule_id, severity, role in rows:
        found.setdefault(event_id, []).append(
            {"finding_id": finding_id, "rule_id": rule_id, "severity": severity, "role": role}
        )
    return found


def _bucket_seconds(span: timedelta, buckets: int) -> int:
    wanted = max(span.total_seconds() / max(buckets, 1), 1)
    for size in _NICE_BUCKETS:
        if size >= wanted:
            return size
    return int(math.ceil(wanted / 86400) * 86400)


def histogram(
    engine: Engine,
    case_id: str,
    flt: EventFilter,
    *,
    buckets: int = 60,
    findings_flt: FindingFilter | None = None,
) -> dict[str, Any]:
    buckets = min(max(buckets, 1), MAX_BUCKETS)
    conditions = _where(case_id, flt, findings_flt)
    stamp = events_table.c.timestamp_utc
    with engine.connect() as conn:
        require_case(conn, case_id)
        bounds = conn.execute(
            select(func.min(stamp), func.max(stamp), func.count(stamp)).where(and_(*conditions))
        ).one()
        unplaced = conn.execute(
            select(func.count()).where(and_(*conditions, stamp.is_(None)))
        ).scalar_one()
        first, last, placed = bounds
        if first is None:
            return {
                "start_utc": None,
                "end_utc": None,
                "bucket_seconds": None,
                "buckets": [],
                "placed": 0,
                "unplaced": unplaced,
            }
        first = from_utc_storage(first) if isinstance(first, str) else first
        last = from_utc_storage(last) if isinstance(last, str) else last
        start = flt.start or first
        end = flt.end or (last + timedelta(seconds=1))
        size = _bucket_seconds(end - start, buckets)
        epoch = int(start.timestamp()) // size * size
        bucket_start = datetime.fromtimestamp(epoch, UTC)
        # Stored timestamps are fixed-width ISO text; the first 19 characters are whole seconds.
        # epoch and size are integers computed here, never user text.
        bucket: ColumnElement[int] = literal_column(
            f"(CAST(strftime('%s', substr(events.timestamp_utc, 1, 19)) AS INTEGER) - {epoch})"
            f" / {size}"
        )
        counts: dict[int, int] = dict(
            conn.execute(
                select(bucket.label("b"), func.count())
                .where(and_(*conditions, stamp.is_not(None)))
                .group_by(text("b"))
            ).all()
        )
        flagged: dict[int, int] = {}
        if findings_flt is not None and findings_flt.run_id:
            flagged = dict(
                conn.execute(
                    select(bucket.label("b"), func.count())
                    .where(
                        and_(*conditions, stamp.is_not(None)),
                        _finding_condition(FindingFilter(run_id=findings_flt.run_id)),
                    )
                    .group_by(text("b"))
                ).all()
            )
    total_buckets = max(math.ceil((end.timestamp() - epoch) / size), 1)
    series = [
        {
            "start_utc": bucket_start + timedelta(seconds=i * size),
            "count": counts.get(i, 0),
            "finding_events": flagged.get(i, 0),
        }
        for i in range(total_buckets)
        if counts.get(i, 0) or total_buckets <= MAX_BUCKETS
    ]
    return {
        "start_utc": bucket_start,
        "end_utc": bucket_start + timedelta(seconds=total_buckets * size),
        "bucket_seconds": size,
        "buckets": series,
        "placed": placed,
        "unplaced": unplaced,
    }
