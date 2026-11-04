"""Event queries for the API."""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, Connection, Engine, and_, func, literal_column, or_, select

from mizar.core.errors import ErrorCode, MizarError
from mizar.db.tables import (
    event_group_members,
    event_groups,
    events,
    parse_results,
    raw_records,
    source_files,
)
from mizar.evidence.service import require_case
from mizar.evidence.store import CHUNK_BYTES, EvidenceStore

MAX_PAGE = 500
# Raw records larger than this are shown truncated (the full record stays in evidence).
MAX_RAW_DISPLAY_BYTES = 1024 * 1024
_TEXT_ENCODINGS = {"utf-8", "utf-16-le", "utf-16-be"}


@dataclass(frozen=True)
class EventFilter:
    source_file_id: str | None = None
    event_type: str | None = None
    event_category: str | None = None
    username: str | None = None
    hostname: str | None = None
    ip: str | None = None
    parsing_status: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    text: str | None = None


# "+case_id" keeps SQLite from choosing the (case_id, timestamp_utc) index when a more
# selective index applies; with it, an IP lookup in 1M events takes 0.1 ms, not ~500 ms.
_CASE_NOT_INDEXED: ColumnElement[str] = literal_column("+events.case_id")


def _conditions(case_id: str, flt: EventFilter) -> list[Any]:
    selective = any(
        value is not None
        for value in (flt.source_file_id, flt.event_type, flt.username, flt.hostname, flt.ip)
    )
    in_case = (_CASE_NOT_INDEXED if selective else events.c.case_id) == case_id
    conditions: list[Any] = [in_case]
    exact = {
        "source_file_id": flt.source_file_id,
        "event_type": flt.event_type,
        "event_category": flt.event_category,
        "username": flt.username,
        "hostname": flt.hostname,
        "parsing_status": flt.parsing_status,
    }
    for column, value in exact.items():
        if value is not None:
            conditions.append(events.c[column] == value)
    if flt.ip is not None:
        conditions.append(or_(events.c.source_ip == flt.ip, events.c.destination_ip == flt.ip))
    if flt.start is not None:
        conditions.append(events.c.timestamp_utc >= flt.start)
    if flt.end is not None:
        conditions.append(events.c.timestamp_utc < flt.end)
    if flt.text:
        escaped = flt.text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(events.c.message.like(f"%{escaped}%", escape="\\"))
    return conditions


def with_parse_constants(conn: Connection, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add the per-parse fields of the event schema (stored once per parse result)."""
    ids = {row["parse_result_id"] for row in rows}
    if not ids:
        return rows
    constants = {
        pid: {"schema_version": schema, "parser_version": version, "ingestion_time": started}
        for pid, schema, version, started in conn.execute(
            select(
                parse_results.c.parse_result_id,
                parse_results.c.schema_version,
                parse_results.c.parser_version,
                parse_results.c.started_at,
            ).where(parse_results.c.parse_result_id.in_(ids))
        )
    }
    return [{**row, **constants[row["parse_result_id"]]} for row in rows]


def list_events(
    engine: Engine, case_id: str, flt: EventFilter, limit: int, offset: int
) -> tuple[list[dict[str, Any]], int]:
    """Events in timeline order (events without UTC time last, in file order)."""
    limit = min(max(limit, 1), MAX_PAGE)
    where = and_(*_conditions(case_id, flt))
    with engine.connect() as conn:
        require_case(conn, case_id)
        total = conn.execute(select(func.count()).select_from(events).where(where)).scalar_one()
        rows = conn.execute(
            select(events)
            .where(where)
            .order_by(
                events.c.timestamp_utc.is_(None),
                events.c.timestamp_utc,
                events.c.source_file_id,
                events.c.record_index,
            )
            .limit(limit)
            .offset(max(offset, 0))
        ).mappings()
        return with_parse_constants(conn, [dict(r) for r in rows]), int(total)


def get_event(engine: Engine, store: EvidenceStore, event_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = conn.execute(select(events).where(events.c.event_id == event_id)).mappings().first()
        if row is None:
            raise MizarError(
                ErrorCode.NOT_FOUND, "Event not found.", details={"event_id": event_id}
            )
        result = with_parse_constants(conn, [dict(row)])[0]
        result["raw_record"] = read_raw_record(conn, store, result)
        groups = conn.execute(
            select(event_groups.c.group_id, event_groups.c.group_type, event_groups.c.member_count)
            .join(event_group_members, event_group_members.c.group_id == event_groups.c.group_id)
            .where(event_group_members.c.event_id == event_id)
        ).all()
        result["groups"] = []
        for group_id, group_type, count in groups:
            members = conn.execute(
                select(events.c.event_id, events.c.source_file_id)
                .join(event_group_members, event_group_members.c.event_id == events.c.event_id)
                .where(event_group_members.c.group_id == group_id)
                .order_by(events.c.source_file_id)
            ).all()
            result["groups"].append(
                {
                    "group_id": group_id,
                    "group_type": group_type,
                    "member_count": count,
                    "members": [
                        {"event_id": m.event_id, "source_file_id": m.source_file_id}
                        for m in members
                    ],
                }
            )
    return result


def read_raw_record(
    conn: Connection, store: EvidenceStore, event: dict[str, Any]
) -> dict[str, Any]:
    """The original record: the stored copy, or read back from evidence and hash-checked."""
    stored = (
        conn.execute(select(raw_records).where(raw_records.c.event_id == event["event_id"]))
        .mappings()
        .first()
    )
    if stored is not None:
        return _stored_view(stored)
    sha256 = conn.execute(
        select(source_files.c.blob_sha256).where(
            source_files.c.source_file_id == event["source_file_id"]
        )
    ).scalar_one()
    return _evidence_view(store, sha256, event)


def _decode(data: bytes, encoding: str) -> tuple[str, bool]:
    text_encoding = "utf-8" if encoding in ("utf-8-sig", "evtx-json-rendering") else encoding
    if text_encoding not in _TEXT_ENCODINGS:
        text_encoding = "utf-8"
    text = data.decode(text_encoding, errors="replace")
    return text, text.encode(text_encoding, errors="replace") == data


def _stored_view(stored: Any) -> dict[str, Any]:
    data = stored["data"]
    if stored["compression"] == "zlib":
        data = zlib.decompress(data)
    text, lossless = _decode(data, stored["encoding"])
    return {
        "source": "stored_copy",
        "encoding": stored["encoding"],
        "size_bytes": stored["size_bytes"],
        "text": text,
        "lossless": lossless,
        "verified": None,
        "display_truncated": False,
    }


def _evidence_view(store: EvidenceStore, sha256: str, event: dict[str, Any]) -> dict[str, Any]:
    """Read the record back from the evidence file and check it against record_hash."""
    locator = event["original_record_reference"]
    if locator["kind"] == "lines":
        ranges = [(offset, length) for offset, length in locator["byte_ranges"]]
    else:
        ranges = [(locator["byte_offset"], locator["byte_length"])]
    digest = hashlib.sha256()
    shown = bytearray()
    total = 0
    with store.open(sha256) as blob:
        for index, (offset, length) in enumerate(ranges):
            if index:
                digest.update(b"\n")
                if len(shown) < MAX_RAW_DISPLAY_BYTES:
                    shown += b"\n"
            blob.seek(offset)
            remaining = length
            while remaining:
                chunk = blob.read(min(CHUNK_BYTES, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                if len(shown) < MAX_RAW_DISPLAY_BYTES:
                    shown += chunk[: MAX_RAW_DISPLAY_BYTES - len(shown)]
                remaining -= len(chunk)
                total += len(chunk)
    text, lossless = _decode(bytes(shown), "utf-8")
    return {
        "source": "evidence_file",
        "encoding": "utf-8",
        "size_bytes": total + max(len(ranges) - 1, 0),
        "text": text,
        "lossless": lossless,
        "verified": digest.hexdigest() == event["record_hash"],
        "display_truncated": len(shown) < total,
    }
