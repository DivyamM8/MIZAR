"""Case index: entities, sessions and documented process links (DESIGN.md §10).

Rebuilt for the whole case by a background job after parsing. Only one copy
of a record collected twice (a duplicate group) is counted, so a log uploaded
twice does not double entity counts or repeat session lines.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, delete, insert, select, text

from mizar.core.timeutil import utc_now
from mizar.db.tables import entities, event_group_members, event_groups, event_links, events
from mizar.jobs import queue

INDEX_JOB = "index_case"
SESSION_GAP = timedelta(hours=8)
_SESSION_SUMMARY_VALUES = 5
# Windows well-known logon IDs (SYSTEM, NETWORK SERVICE, LOCAL SERVICE, none): every
# service shares them, so they do not identify an interactive session.
_SHARED_SESSION_IDS = frozenset({"0x3e7", "0x3e4", "0x3e5", "0x0", "0"})
_CLOSING_TYPES = frozenset({"logoff", "session_closed", "session_disconnected"})

# Non-first members of each duplicate group: the same record already counted elsewhere.
_DUPLICATE_COPIES = """
    SELECT m.event_id FROM event_group_members m
    JOIN event_groups g ON g.group_id = m.group_id
    JOIN events e ON e.event_id = m.event_id
    WHERE g.case_id = :case_id AND g.group_type = 'duplicate'
      AND EXISTS (
        SELECT 1 FROM event_group_members m2 JOIN events e2 ON e2.event_id = m2.event_id
        WHERE m2.group_id = m.group_id
          AND (e2.source_file_id, e2.record_index) < (e.source_file_id, e.record_index)
      )
"""

_ENTITY_SQL = {
    "host": "hostname",
    "user": "username",
}


def queue_index(conn: Connection, case_id: str) -> str | None:
    """Queue a rebuild unless one is already waiting (it will see the new events too)."""
    from mizar.db.tables import jobs

    waiting = conn.execute(
        select(jobs.c.job_id).where(
            jobs.c.case_id == case_id, jobs.c.job_type == INDEX_JOB, jobs.c.status == "queued"
        )
    ).first()
    if waiting is not None:
        return None
    return queue.enqueue(conn, INDEX_JOB, {"case_id": case_id}, case_id)


def _copies(conn: Connection, case_id: str) -> set[str]:
    return {row[0] for row in conn.execute(text(_DUPLICATE_COPIES), {"case_id": case_id})}


def rebuild_entities(engine: Engine, case_id: str) -> int:
    # Aggregate in a read transaction (WAL lets writers continue), then swap the rows in a
    # short write, so uploads and edits are never blocked behind a long rebuild.
    not_copy = f"event_id NOT IN ({_DUPLICATE_COPIES})"
    rows: list[dict[str, Any]] = []
    with engine.connect() as conn:
        for entity_type, column in _ENTITY_SQL.items():
            result = conn.execute(
                text(
                    f"""
                    SELECT {column} AS value, COUNT(*) AS n,
                           SUM(timestamp_utc IS NULL) AS unplaced,
                           MIN(timestamp_utc) AS first, MAX(timestamp_utc) AS last,
                           json_group_array(DISTINCT source_file_id) AS files
                    FROM events
                    WHERE case_id = :case_id AND {column} IS NOT NULL AND {not_copy}
                    GROUP BY {column}
                    """  # noqa: S608 (column names and the subquery are constants)
                ),
                {"case_id": case_id},
            )
            rows.extend(_entity_row(case_id, entity_type, r, None, None) for r in result.mappings())
        result = conn.execute(
            text(
                f"""
                SELECT value, COUNT(*) AS n, SUM(ts IS NULL) AS unplaced,
                       MIN(ts) AS first, MAX(ts) AS last,
                       SUM(role = 'source') AS as_source, SUM(role = 'destination') AS as_dest,
                       json_group_array(DISTINCT file) AS files
                FROM (
                    SELECT source_ip AS value, 'source' AS role, timestamp_utc AS ts,
                           source_file_id AS file, event_id
                    FROM events WHERE case_id = :case_id AND source_ip IS NOT NULL
                    UNION ALL
                    SELECT destination_ip, 'destination', timestamp_utc, source_file_id, event_id
                    FROM events WHERE case_id = :case_id AND destination_ip IS NOT NULL
                )
                WHERE {not_copy}
                GROUP BY value
                """  # noqa: S608 (the subquery is a constant)
            ),
            {"case_id": case_id},
        )
        rows.extend(
            _entity_row(case_id, "ip", r, r["as_source"], r["as_dest"]) for r in result.mappings()
        )
    with engine.begin() as conn:
        conn.execute(delete(entities).where(entities.c.case_id == case_id))
        for start in range(0, len(rows), 5000):
            conn.execute(insert(entities), rows[start : start + 5000])
    return len(rows)


def _entity_row(
    case_id: str, entity_type: str, row: Any, as_source: int | None, as_destination: int | None
) -> dict[str, Any]:
    from mizar.core.timeutil import from_utc_storage

    return {
        "case_id": case_id,
        "entity_type": entity_type,
        "value": row["value"],
        "event_count": row["n"],
        "unplaced_count": row["unplaced"] or 0,
        "first_seen_utc": from_utc_storage(row["first"]) if row["first"] else None,
        "last_seen_utc": from_utc_storage(row["last"]) if row["last"] else None,
        "as_source": as_source,
        "as_destination": as_destination,
        "source_file_ids": sorted(json.loads(row["files"])),
    }


def _session_id(case_id: str, hostname: str | None, session: str, first_event: str) -> str:
    digest = hashlib.sha256(f"{case_id}|session|{hostname}|{session}|{first_event}".encode())
    return "SES-" + digest.hexdigest()[:24]


def _summarize(members: list[dict[str, Any]]) -> dict[str, Any]:
    def top(field: str) -> list[str]:
        counts = Counter(str(m[field]) for m in members if m[field] is not None)
        return [value for value, _ in counts.most_common(_SESSION_SUMMARY_VALUES)]

    types = Counter(m["event_type"] for m in members if m["event_type"])
    stamps = [m["timestamp_utc"] for m in members if m["timestamp_utc"] is not None]
    return {
        "hostname": members[0]["hostname"],
        "session_id": members[0]["session_id"],
        "usernames": top("username"),
        "source_ips": top("source_ip"),
        "event_types": types.most_common(10),
        "first_event_type": members[0]["event_type"],
        "closed": any(m["event_type"] in _CLOSING_TYPES for m in members),
        "events_without_utc": len(members) - len(stamps),
        "source_file_ids": sorted({m["source_file_id"] for m in members}),
    }


def rebuild_sessions(engine: Engine, case_id: str, gap: timedelta = SESSION_GAP) -> int:
    """Group events sharing (hostname, session_id); split where the gap exceeds `gap`."""
    columns = [
        events.c.event_id,
        events.c.hostname,
        events.c.session_id,
        events.c.timestamp_utc,
        events.c.username,
        events.c.source_ip,
        events.c.event_type,
        events.c.source_file_id,
        events.c.record_index,
    ]
    with engine.connect() as conn:
        copies = _copies(conn, case_id)
        query = (
            select(*columns)
            .where(
                events.c.case_id == case_id,
                events.c.session_id.is_not(None),
                events.c.session_id.not_in(_SHARED_SESSION_IDS),
            )
            .order_by(
                events.c.hostname,
                events.c.session_id,
                events.c.timestamp_utc.is_(None),
                events.c.timestamp_utc,
                events.c.source_file_id,
                events.c.record_index,
            )
        )
        groups: list[dict[str, Any]] = []
        links: list[dict[str, str]] = []
        now = utc_now()
        current: list[dict[str, Any]] = []

        def flush() -> None:
            if len(current) >= 2:
                group_id = _session_id(
                    case_id,
                    current[0]["hostname"],
                    current[0]["session_id"],
                    current[0]["event_id"],
                )
                stamps = [m["timestamp_utc"] for m in current if m["timestamp_utc"] is not None]
                groups.append(
                    {
                        "group_id": group_id,
                        "case_id": case_id,
                        "group_type": "session",
                        "group_key": f"{current[0]['hostname']}|{current[0]['session_id']}",
                        "member_count": len(current),
                        "summary": _summarize(current),
                        "first_utc": min(stamps) if stamps else None,
                        "last_utc": max(stamps) if stamps else None,
                        "created_at": now,
                    }
                )
                links.extend({"group_id": group_id, "event_id": m["event_id"]} for m in current)
            current.clear()

        last_stamp: datetime | None = None
        for row in conn.execute(query.execution_options(yield_per=5000)).mappings():
            member = dict(row)
            if member["event_id"] in copies:
                continue
            stamp = member["timestamp_utc"]
            same_key = bool(current) and (
                (current[0]["hostname"], current[0]["session_id"])
                == (member["hostname"], member["session_id"])
            )
            if not same_key or (stamp and last_stamp and stamp - last_stamp > gap):
                flush()
                last_stamp = None
            current.append(member)
            last_stamp = stamp or last_stamp
        flush()
    with engine.begin() as conn:
        conn.execute(
            delete(event_groups).where(
                event_groups.c.case_id == case_id, event_groups.c.group_type == "session"
            )
        )
        for start in range(0, len(groups), 2000):
            conn.execute(insert(event_groups), groups[start : start + 2000])
        for start in range(0, len(links), 5000):
            conn.execute(insert(event_group_members), links[start : start + 5000])
    return len(groups)


def rebuild_process_links(engine: Engine, case_id: str) -> int:
    """Sysmon: process creation -> child creation, and -> the process's own activity."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT event_id, event_type,
                       json_extract(extra, '$.process_guid') AS guid,
                       json_extract(extra, '$.parent_process_guid') AS parent_guid,
                       json_extract(extra, '$.event_data.ProcessGuid') AS actor_guid
                FROM events
                WHERE case_id = :case_id
                  AND source_type IN ('windows_evtx', 'windows_evtx_export')
                  AND json_extract(extra, '$.provider') = 'Microsoft-Windows-Sysmon'
                ORDER BY timestamp_utc IS NULL, timestamp_utc, source_file_id, record_index
                """
            ),
            {"case_id": case_id},
        ).mappings()
        created: dict[str, str] = {}
        pending: list[Any] = []
        for row in rows:
            if row["event_type"] == "process_created" and row["guid"]:
                created.setdefault(row["guid"], row["event_id"])
            pending.append(row)
        found: list[dict[str, Any]] = []
        for row in pending:
            if row["event_type"] == "process_created":
                parent = created.get(row["parent_guid"]) if row["parent_guid"] else None
                if parent is not None and parent != row["event_id"]:
                    found.append(
                        _link(
                            case_id,
                            parent,
                            row["event_id"],
                            "parent_process_of",
                            row["parent_guid"],
                        )
                    )
            elif row["actor_guid"]:
                creator = created.get(row["actor_guid"])
                if creator is not None:
                    found.append(
                        _link(
                            case_id,
                            creator,
                            row["event_id"],
                            "process_performed",
                            row["actor_guid"],
                        )
                    )
    with engine.begin() as conn:
        conn.execute(delete(event_links).where(event_links.c.case_id == case_id))
        for start in range(0, len(found), 5000):
            conn.execute(insert(event_links), found[start : start + 5000])
    return len(found)


def _link(case_id: str, source: str, target: str, kind: str, guid: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "from_event_id": source,
        "to_event_id": target,
        "link_type": kind,
        "basis": {"field": "ProcessGuid", "value": guid},
    }


def rebuild_case_index(engine: Engine, case_id: str) -> dict[str, int]:
    return {
        "entities": rebuild_entities(engine, case_id),
        "sessions": rebuild_sessions(engine, case_id),
        "process_links": rebuild_process_links(engine, case_id),
    }
