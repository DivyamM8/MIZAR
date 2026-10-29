"""Duplicate groups (DESIGN.md §8): the same record collected in more than one file.

Nothing is deleted. Identical raw bytes in *different* source files form a
group; identical lines within one file are distinct records and are never
grouped. If a record occurs k times in file A and k times in file B (e.g. an
overlapping rotated copy), the n-th occurrence in A is grouped with the n-th
in B.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from sqlalchemy import Engine, delete, insert, select, text

from mizar.core.timeutil import utc_now
from mizar.db.tables import event_group_members, event_groups, events

_DUPLICATE_CANDIDATES = text(
    """
    WITH shared AS (
        SELECT record_hash FROM events
        WHERE case_id = :case_id
        GROUP BY record_hash
        HAVING COUNT(DISTINCT source_file_id) > 1
    ),
    numbered AS (
        SELECT e.event_id, e.record_hash, e.source_file_id,
               ROW_NUMBER() OVER (
                   PARTITION BY e.source_file_id, e.record_hash ORDER BY e.record_index
               ) AS occurrence
        FROM events e JOIN shared s ON s.record_hash = e.record_hash
        WHERE e.case_id = :case_id
    )
    SELECT record_hash, occurrence, event_id, source_file_id
    FROM numbered
    ORDER BY record_hash, occurrence, source_file_id
    """
)


def needs_rebuild(engine: Engine, case_id: str, source_file_id: str) -> bool:
    """True if the file shares records with another file, or groups already exist."""
    with engine.connect() as conn:
        existing = conn.execute(
            select(event_groups.c.group_id)
            .where(event_groups.c.case_id == case_id, event_groups.c.group_type == "duplicate")
            .limit(1)
        ).first()
        if existing is not None:
            return True
        other = events.alias("other")
        shared = conn.execute(
            select(events.c.event_id)
            .join(
                other,
                (other.c.record_hash == events.c.record_hash)
                & (other.c.case_id == events.c.case_id)
                & (other.c.source_file_id != events.c.source_file_id),
            )
            .where(events.c.source_file_id == source_file_id)
            .limit(1)
        ).first()
    return shared is not None


def rebuild_duplicate_groups(engine: Engine, case_id: str) -> int:
    """Recompute all duplicate groups of a case. Returns the number of groups."""
    with engine.begin() as conn:
        conn.execute(
            delete(event_groups).where(
                event_groups.c.case_id == case_id, event_groups.c.group_type == "duplicate"
            )
        )
        members: dict[tuple[str, int], list[tuple[str, str]]] = defaultdict(list)
        for record_hash, occurrence, event_id, source_file_id in conn.execute(
            _DUPLICATE_CANDIDATES, {"case_id": case_id}
        ):
            members[(record_hash, occurrence)].append((event_id, source_file_id))
        now = utc_now()
        groups: list[dict[str, object]] = []
        links: list[dict[str, str]] = []
        for (record_hash, occurrence), found in members.items():
            if len({file_id for _, file_id in found}) < 2:
                continue
            key = f"{record_hash}:{occurrence}"
            group_id = (
                "EG-" + hashlib.sha256(f"{case_id}|duplicate|{key}".encode()).hexdigest()[:24]
            )
            groups.append(
                {
                    "group_id": group_id,
                    "case_id": case_id,
                    "group_type": "duplicate",
                    "group_key": key,
                    "member_count": len(found),
                    "created_at": now,
                }
            )
            links.extend({"group_id": group_id, "event_id": event_id} for event_id, _ in found)
        if groups:
            conn.execute(insert(event_groups), groups)
            conn.execute(insert(event_group_members), links)
    return len(groups)
