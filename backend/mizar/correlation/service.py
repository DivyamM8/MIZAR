"""Entities, sessions, documented links and on-demand related events (DESIGN.md §10)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import ColumnElement, Engine, and_, func, literal_column, or_, select, text

from mizar.core.errors import ErrorCode, MizarError
from mizar.correlation.index import INDEX_JOB
from mizar.correlation.timeline import _COLUMNS, latest_run_id
from mizar.db.tables import (
    ENTITY_TYPES,
    entities,
    event_group_members,
    event_groups,
    event_links,
    events,
    findings,
    jobs,
)
from mizar.detection.rules import SEVERITIES
from mizar.evidence.service import require_case

MAX_PAGE = 500
RELATED_FIELDS = ("source_ip", "destination_ip", "username", "hostname")
_FINDING_ENTITY_FIELDS = {
    "host": ("hostname",),
    "user": ("username",),
    "ip": ("source_ip", "destination_ip"),
}
_CASE_NOT_INDEXED: ColumnElement[str] = literal_column("+events.case_id")


def index_state(engine: Engine, case_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = (
            conn.execute(
                select(jobs.c.job_id, jobs.c.status, jobs.c.finished_at, jobs.c.error_code)
                .where(jobs.c.case_id == case_id, jobs.c.job_type == INDEX_JOB)
                .order_by(jobs.c.created_at.desc())
                .limit(1)
            )
            .mappings()
            .first()
        )
    if row is None:
        return {"status": "not_built", "job_id": None, "built_at": None}
    return {
        "status": {"succeeded": "current"}.get(row["status"], row["status"]),
        "job_id": row["job_id"],
        "built_at": row["finished_at"],
        "error_code": row["error_code"],
    }


def _finding_counts(
    engine: Engine, case_id: str, run_id: str | None
) -> dict[tuple[str, str], dict[str, int]]:
    """Per entity: number of findings of the run naming it, by severity."""
    if run_id is None:
        return {}
    counts: dict[tuple[str, str], dict[str, int]] = {}
    with engine.connect() as conn:
        rows = conn.execute(
            select(findings.c.entities, findings.c.severity).where(findings.c.run_id == run_id)
        ).all()
    for found, severity in rows:
        for entity_type, fields in _FINDING_ENTITY_FIELDS.items():
            values: set[str] = set()
            for name in fields:
                value = found.get(name)
                for item in value if isinstance(value, list) else [value]:
                    if item is not None:
                        values.add(str(item))
            for value in values:
                bucket = counts.setdefault((entity_type, value), {})
                bucket[severity] = bucket.get(severity, 0) + 1
    return counts


def _with_findings(
    row: dict[str, Any], counts: dict[tuple[str, str], dict[str, int]]
) -> dict[str, Any]:
    by_severity = counts.get((row["entity_type"], row["value"]), {})
    highest = max(by_severity, key=SEVERITIES.index) if by_severity else None
    return {
        **row,
        "finding_count": sum(by_severity.values()),
        "findings_by_severity": by_severity,
        "highest_severity": highest,
    }


def list_entities(
    engine: Engine,
    case_id: str,
    *,
    entity_type: str | None,
    query: str | None,
    limit: int,
    offset: int,
    run_id: str | None,
) -> dict[str, Any]:
    if entity_type is not None and entity_type not in ENTITY_TYPES:
        raise MizarError(
            ErrorCode.VALIDATION_ERROR, f"type must be one of {', '.join(ENTITY_TYPES)}."
        )
    conditions = [entities.c.case_id == case_id]
    if entity_type:
        conditions.append(entities.c.entity_type == entity_type)
    if query:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append(entities.c.value.like(f"%{escaped}%", escape="\\"))
    with engine.connect() as conn:
        require_case(conn, case_id)
        total = conn.execute(
            select(func.count()).select_from(entities).where(*conditions)
        ).scalar_one()
        rows = [
            dict(r)
            for r in conn.execute(
                select(entities)
                .where(*conditions)
                .order_by(entities.c.event_count.desc(), entities.c.entity_type, entities.c.value)
                .limit(min(max(limit, 1), MAX_PAGE))
                .offset(max(offset, 0))
            ).mappings()
        ]
    run_id = run_id or latest_run_id(engine, case_id)
    counts = _finding_counts(engine, case_id, run_id)
    return {
        "items": [_with_findings(r, counts) for r in rows],
        "total": total,
        "run_id": run_id,
        "index": index_state(engine, case_id),
    }


def get_entity(
    engine: Engine, case_id: str, entity_type: str, value: str, run_id: str | None
) -> dict[str, Any]:
    with engine.connect() as conn:
        require_case(conn, case_id)
        row = (
            conn.execute(
                select(entities).where(
                    entities.c.case_id == case_id,
                    entities.c.entity_type == entity_type,
                    entities.c.value == value,
                )
            )
            .mappings()
            .first()
        )
    if row is None:
        raise MizarError(
            ErrorCode.NOT_FOUND,
            "Entity not found (the case index may still be building).",
            details={"entity_type": entity_type, "value": value},
        )
    run_id = run_id or latest_run_id(engine, case_id)
    related: list[dict[str, Any]] = []
    if run_id:
        with engine.connect() as conn:
            for found in conn.execute(
                select(
                    findings.c.finding_id,
                    findings.c.rule_id,
                    findings.c.title,
                    findings.c.severity,
                    findings.c.confidence,
                    findings.c.entities,
                ).where(findings.c.run_id == run_id)
            ).mappings():
                names = _FINDING_ENTITY_FIELDS[entity_type]
                values = {
                    str(item)
                    for name in names
                    for item in (
                        found["entities"].get(name)
                        if isinstance(found["entities"].get(name), list)
                        else [found["entities"].get(name)]
                    )
                    if item is not None
                }
                if value in values:
                    related.append(
                        {
                            k: found[k]
                            for k in ("finding_id", "rule_id", "title", "severity", "confidence")
                        }
                    )
    related.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["finding_id"]))
    by = _session_filter(entity_type)
    sessions = list_sessions(
        engine,
        case_id,
        hostname=value if by == "hostname" else None,
        username=value if by == "username" else None,
        ip=value if by == "ip" else None,
        limit=50,
    )["items"]
    counts = _finding_counts(engine, case_id, run_id)
    return {
        **_with_findings(dict(row), counts),
        "run_id": run_id,
        "findings": related,
        "sessions": sessions,
    }


def _session_filter(entity_type: str) -> str:
    return {"host": "hostname", "user": "username", "ip": "ip"}[entity_type]


def list_sessions(
    engine: Engine,
    case_id: str,
    *,
    hostname: str | None = None,
    username: str | None = None,
    ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    conditions: list[Any] = [
        event_groups.c.case_id == case_id,
        event_groups.c.group_type == "session",
    ]
    if hostname:
        conditions.append(func.json_extract(event_groups.c.summary, "$.hostname") == hostname)
    for name, value in (("usernames", username), ("source_ips", ip)):
        if value:
            # Exact element match in the summary's JSON array.
            conditions.append(
                text(
                    # name comes from the fixed tuple above; the value is a bound parameter.
                    f"EXISTS (SELECT 1 FROM json_each(event_groups.summary, :{name}_path) "  # noqa: S608
                    f"WHERE json_each.value = :{name}_value)"
                ).bindparams(**{f"{name}_path": f"$.{name}", f"{name}_value": value})
            )
    with engine.connect() as conn:
        require_case(conn, case_id)
        total = conn.execute(
            select(func.count()).select_from(event_groups).where(*conditions)
        ).scalar_one()
        rows = conn.execute(
            select(event_groups)
            .where(*conditions)
            .order_by(
                event_groups.c.first_utc.is_(None),
                event_groups.c.first_utc,
                event_groups.c.group_id,
            )
            .limit(min(max(limit, 1), MAX_PAGE))
            .offset(max(offset, 0))
        ).mappings()
        items = [_session_out(dict(r)) for r in rows]
    return {"items": items, "total": total}


def _session_out(row: dict[str, Any]) -> dict[str, Any]:
    summary = row.get("summary") or {}
    return {
        "session_group_id": row["group_id"],
        "case_id": row["case_id"],
        "hostname": summary.get("hostname"),
        "session_id": summary.get("session_id"),
        "event_count": row["member_count"],
        "first_utc": row["first_utc"],
        "last_utc": row["last_utc"],
        "usernames": summary.get("usernames", []),
        "source_ips": summary.get("source_ips", []),
        "event_types": summary.get("event_types", []),
        "first_event_type": summary.get("first_event_type"),
        "closed": summary.get("closed", False),
        "events_without_utc": summary.get("events_without_utc", 0),
        "source_file_ids": summary.get("source_file_ids", []),
    }


def get_session(
    engine: Engine, group_id: str, *, limit: int = 200, offset: int = 0
) -> dict[str, Any]:
    with engine.connect() as conn:
        row = (
            conn.execute(
                select(event_groups).where(
                    event_groups.c.group_id == group_id, event_groups.c.group_type == "session"
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise MizarError(
                ErrorCode.NOT_FOUND, "Session not found.", details={"session_group_id": group_id}
            )
        members = [
            dict(r)
            for r in conn.execute(
                select(*_COLUMNS)
                .join(event_group_members, event_group_members.c.event_id == events.c.event_id)
                .where(event_group_members.c.group_id == group_id)
                .order_by(
                    events.c.timestamp_utc.is_(None),
                    events.c.timestamp_utc,
                    events.c.source_file_id,
                    events.c.record_index,
                )
                .limit(min(max(limit, 1), MAX_PAGE))
                .offset(max(offset, 0))
            ).mappings()
        ]
    return {**_session_out(dict(row)), "events": members, "offset": offset}


def event_links_for(engine: Engine, event_id: str) -> dict[str, list[dict[str, Any]]]:
    """Documented links (ProcessGuid) into and out of an event."""
    with engine.connect() as conn:
        rows = conn.execute(
            select(event_links)
            .where(
                or_(event_links.c.from_event_id == event_id, event_links.c.to_event_id == event_id)
            )
            .order_by(event_links.c.link_id)
        ).mappings()
        outgoing: list[dict[str, Any]] = []
        incoming: list[dict[str, Any]] = []
        for row in rows:
            item = {
                "link_type": row["link_type"],
                "basis": row["basis"],
                "event_id": row["to_event_id"]
                if row["from_event_id"] == event_id
                else row["from_event_id"],
            }
            (outgoing if row["from_event_id"] == event_id else incoming).append(item)
    return {"outgoing": outgoing, "incoming": incoming}


def related_events(
    engine: Engine, event_id: str, *, field: str, window: timedelta, limit: int = 100
) -> dict[str, Any]:
    """Events sharing a field value within ±window. Shared attributes, not causation."""
    if field not in RELATED_FIELDS:
        raise MizarError(
            ErrorCode.VALIDATION_ERROR, f"field must be one of {', '.join(RELATED_FIELDS)}."
        )
    with engine.connect() as conn:
        anchor = conn.execute(
            select(events.c.case_id, events.c.timestamp_utc, events.c[field]).where(
                events.c.event_id == event_id
            )
        ).first()
        if anchor is None:
            raise MizarError(
                ErrorCode.NOT_FOUND, "Event not found.", details={"event_id": event_id}
            )
        case_id, stamp, value = anchor
        basis = {"field": field, "value": value, "window_seconds": int(window.total_seconds())}
        if value is None or stamp is None:
            reason = (
                "the event has no value for this field"
                if value is None
                else "the event has no reliable UTC time"
            )
            return {"basis": basis, "items": [], "note": f"No related events: {reason}."}
        columns = (
            [events.c.source_ip, events.c.destination_ip]
            if field in ("source_ip", "destination_ip")
            else [events.c[field]]
        )
        match = or_(*(c == value for c in columns))
        rows = conn.execute(
            select(*_COLUMNS)
            .where(
                case_id == _CASE_NOT_INDEXED,
                match,
                events.c.event_id != event_id,
                and_(
                    events.c.timestamp_utc >= stamp - window,
                    events.c.timestamp_utc <= stamp + window,
                ),
            )
            .order_by(events.c.timestamp_utc, events.c.source_file_id, events.c.record_index)
            .limit(min(max(limit, 1), MAX_PAGE))
        ).mappings()
        items = [dict(r) for r in rows]
    return {
        "basis": basis,
        "items": items,
        "note": f"Related by {field} = {value} within {int(window.total_seconds())}s. "
        "Sharing an attribute and time does not show that one event caused another.",
    }
