"""Normalized event endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from mizar.api.deps import EngineDep, StoreDep
from mizar.api.schemas import EventDetail, EventLinks, EventOut, EventPage
from mizar.core.errors import ErrorCode, MizarError
from mizar.correlation.service import event_links_for
from mizar.events.service import MAX_PAGE, EventFilter, get_event, list_events

router = APIRouter(tags=["events"])


@router.get("/api/cases/{case_id}/events")
def search_events(
    case_id: str,
    engine: EngineDep,
    source_file_id: str | None = None,
    event_type: str | None = None,
    event_category: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    ip: Annotated[str | None, Query(description="Matches source or destination IP")] = None,
    parsing_status: str | None = None,
    start: Annotated[datetime | None, Query(description="UTC, inclusive")] = None,
    end: Annotated[datetime | None, Query(description="UTC, exclusive")] = None,
    q: Annotated[str | None, Query(max_length=200, description="Substring of message")] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
    for name, value in (("start", start), ("end", end)):
        if value is not None and value.utcoffset() is None:
            raise MizarError(
                ErrorCode.VALIDATION_ERROR,
                "The request is invalid.",
                details={
                    "errors": [
                        {
                            "loc": ["query", name],
                            "msg": "timestamp must include a timezone offset, e.g. Z",
                            "type": "value_error",
                        }
                    ]
                },
            )
    flt = EventFilter(
        source_file_id=source_file_id,
        event_type=event_type,
        event_category=event_category,
        username=username,
        hostname=hostname,
        ip=ip,
        parsing_status=parsing_status,
        start=start,
        end=end,
        text=q,
    )
    rows, total = list_events(engine, case_id, flt, limit, offset)
    return EventPage(items=[EventOut(**r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/api/events/{event_id}")
def event_detail(event_id: str, engine: EngineDep, store: StoreDep) -> EventDetail:
    return EventDetail(
        **get_event(engine, store, event_id),
        links=EventLinks.model_validate(event_links_for(engine, event_id)),
    )
