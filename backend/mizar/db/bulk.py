"""Loading large files without the random-key event indexes (DESIGN.md D48).

Event IDs, record hashes, IP addresses and session IDs are effectively random keys.
Once a case holds millions of events, every inserted row touches a different page
of each of these indexes, and every touched page is rewritten at commit. Measured on
a 13.7M-event case: about 1,600 events/s and 269 GB written to disk. For a large
file the indexes are dropped, the rows appended, and the indexes rebuilt in one
sorted pass (about 30 s each at 13.7M events).

While they are missing, lookups on those columns scan the table and deletes from
`events` cannot run (SQLite checks child foreign keys through the event ID index),
so case deletion is refused until the load finishes.
"""

from __future__ import annotations

import logging

from sqlalchemy import Connection, Engine, Index, text

from mizar.db.tables import events

log = logging.getLogger(__name__)

_DEFERRED_COLUMNS = ("event_id", "record_hash", "source_ip", "destination_ip", "session_id")
DEFERRED_INDEXES: tuple[Index, ...] = tuple(
    index
    for index in sorted(events.indexes, key=lambda i: str(i.name))
    if [c.name for c in index.columns] in ([name] for name in _DEFERRED_COLUMNS)
)
_EVENT_ID_INDEX = next(i for i in DEFERRED_INDEXES if [c.name for c in i.columns] == ["event_id"])


def drop_deferred_indexes(conn: Connection) -> None:
    for index in DEFERRED_INDEXES:
        index.drop(conn, checkfirst=True)


def restore_deferred_indexes(conn: Connection) -> list[str]:
    """Create whichever deferred indexes are missing. Returns their names."""
    created = []
    for index in DEFERRED_INDEXES:
        if not _exists(conn, str(index.name)):
            index.create(conn)
            created.append(str(index.name))
    return created


def ensure_event_indexes(engine: Engine) -> None:
    """Restore indexes left missing by an interrupted bulk load (worker start-up)."""
    with engine.begin() as conn:
        created = restore_deferred_indexes(conn)
    if created:
        log.warning("restored event indexes left by an interrupted load: %s", ", ".join(created))


def bulk_load_in_progress(conn: Connection) -> bool:
    return not _exists(conn, str(_EVENT_ID_INDEX.name))


def _exists(conn: Connection, name: str) -> bool:
    found = conn.execute(
        text("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :name"),
        {"name": name},
    ).first()
    return found is not None
