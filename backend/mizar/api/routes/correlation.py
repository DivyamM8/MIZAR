"""Timeline, entities, sessions and related events."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, status

from mizar.api.deps import EngineDep
from mizar.api.schemas import (
    EntityDetail,
    EntityPage,
    Histogram,
    JobQueued,
    RelatedEvents,
    SessionDetail,
    SessionPage,
    TimelinePage,
)
from mizar.core.errors import ErrorCode, MizarError
from mizar.correlation import service
from mizar.correlation.index import queue_index
from mizar.correlation.timeline import FindingFilter, histogram, latest_run_id, page
from mizar.detection.rules import SEVERITIES, parse_duration
from mizar.events.service import EventFilter
from mizar.evidence.service import require_case

router = APIRouter(tags=["correlation"])

Text = Annotated[str | None, Query(max_length=500)]


def _invalid(field: str, message: str) -> MizarError:
    return MizarError(
        ErrorCode.VALIDATION_ERROR,
        "The request is invalid.",
        details={"errors": [{"loc": ["query", field], "msg": message, "type": "value_error"}]},
    )


def build_filter(
    *,
    source_file_id: str | None = None,
    event_type: str | None = None,
    event_category: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    q: str | None = None,
) -> EventFilter:
    for name, value in (("start", start), ("end", end)):
        if value is not None and value.utcoffset() is None:
            raise _invalid(name, "timestamp must include a timezone offset, e.g. Z")
    return EventFilter(
        source_file_id=source_file_id,
        event_type=event_type,
        event_category=event_category,
        username=username,
        hostname=hostname,
        ip=ip,
        start=start,
        end=end,
        text=q,
    )


def _findings_filter(
    engine: EngineDep,
    case_id: str,
    run_id: str | None,
    min_severity: str | None,
    finding_id: str | None,
) -> FindingFilter:
    if min_severity is not None and min_severity not in SEVERITIES:
        raise _invalid("min_severity", f"must be one of {', '.join(SEVERITIES)}")
    return FindingFilter(
        run_id=run_id or latest_run_id(engine, case_id),
        min_severity=min_severity,
        finding_id=finding_id,
    )


@router.get("/api/cases/{case_id}/timeline")
def timeline(
    case_id: str,
    engine: EngineDep,
    lane: Annotated[str, Query(pattern="^(placed|unplaced)$")] = "placed",
    after: Text = None,
    before: Text = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    source_file_id: Text = None,
    event_type: Text = None,
    event_category: Text = None,
    username: Text = None,
    hostname: Text = None,
    ip: Text = None,
    start: datetime | None = None,
    end: datetime | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    run_id: Text = None,
    min_severity: Text = None,
    finding_id: Text = None,
) -> TimelinePage:
    """Placed events in UTC order (keyset paging), or the unplaced lane in file order.

    Finding markers come from run_id, or the latest successful run.
    """
    flt = build_filter(
        source_file_id=source_file_id,
        event_type=event_type,
        event_category=event_category,
        username=username,
        hostname=hostname,
        ip=ip,
        start=start,
        end=end,
        q=q,
    )
    findings = _findings_filter(engine, case_id, run_id, min_severity, finding_id)
    return TimelinePage(
        **page(
            engine,
            case_id,
            flt,
            lane=lane,
            after=after,
            before=before,
            limit=limit,
            findings_flt=findings,
        )
    )


@router.get("/api/cases/{case_id}/timeline/histogram")
def timeline_histogram(
    case_id: str,
    engine: EngineDep,
    buckets: Annotated[int, Query(ge=1, le=500)] = 60,
    source_file_id: Text = None,
    event_type: Text = None,
    event_category: Text = None,
    username: Text = None,
    hostname: Text = None,
    ip: Text = None,
    start: datetime | None = None,
    end: datetime | None = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    run_id: Text = None,
    min_severity: Text = None,
    finding_id: Text = None,
) -> Histogram:
    flt = build_filter(
        source_file_id=source_file_id,
        event_type=event_type,
        event_category=event_category,
        username=username,
        hostname=hostname,
        ip=ip,
        start=start,
        end=end,
        q=q,
    )
    findings = _findings_filter(engine, case_id, run_id, min_severity, finding_id)
    return Histogram(**histogram(engine, case_id, flt, buckets=buckets, findings_flt=findings))


@router.get("/api/cases/{case_id}/entities")
def list_entities(
    case_id: str,
    engine: EngineDep,
    entity_type: Annotated[str | None, Query(alias="type")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    run_id: Text = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EntityPage:
    return EntityPage(
        **service.list_entities(
            engine,
            case_id,
            entity_type=entity_type,
            query=q,
            limit=limit,
            offset=offset,
            run_id=run_id,
        )
    )


@router.get("/api/cases/{case_id}/entity")
def get_entity(
    case_id: str,
    engine: EngineDep,
    entity_type: Annotated[str, Query(alias="type", pattern="^(host|user|ip)$")],
    value: Annotated[str, Query(min_length=1, max_length=1000)],
    run_id: Text = None,
) -> EntityDetail:
    return EntityDetail(**service.get_entity(engine, case_id, entity_type, value, run_id))


@router.post("/api/cases/{case_id}/index", status_code=status.HTTP_202_ACCEPTED)
def rebuild_index(case_id: str, engine: EngineDep) -> JobQueued:
    """Rebuild entities, sessions and process links (normally automatic after parsing)."""
    with engine.begin() as conn:
        require_case(conn, case_id)
        job_id = queue_index(conn, case_id)
    if job_id is None:
        state = service.index_state(engine, case_id)
        job_id = str(state["job_id"])
    return JobQueued(job_id=job_id)


@router.get("/api/cases/{case_id}/sessions")
def list_sessions(
    case_id: str,
    engine: EngineDep,
    hostname: Text = None,
    username: Text = None,
    ip: Text = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SessionPage:
    return SessionPage(
        **service.list_sessions(
            engine, case_id, hostname=hostname, username=username, ip=ip, limit=limit, offset=offset
        )
    )


@router.get("/api/sessions/{session_group_id}")
def get_session(
    session_group_id: str,
    engine: EngineDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SessionDetail:
    return SessionDetail(
        **service.get_session(engine, session_group_id, limit=limit, offset=offset)
    )


@router.get("/api/events/{event_id}/related")
def related(
    event_id: str,
    engine: EngineDep,
    field: Annotated[
        str, Query(pattern="^(source_ip|destination_ip|username|hostname)$")
    ] = "source_ip",
    window: Annotated[str, Query(max_length=10)] = "30m",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> RelatedEvents:
    """Events sharing a value within ±window. A shared attribute, not a causal link."""
    try:
        span = parse_duration(window)
    except ValueError as exc:
        raise _invalid("window", str(exc)) from exc
    return RelatedEvents(
        **service.related_events(engine, event_id, field=field, window=span, limit=limit)
    )
