"""SQLite engine setup and schema migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
# Page cache per connection, in KiB.
PAGE_CACHE_KIB = 64 * 1024


def _set_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        # Writers wait up to 60 s for the single SQLite write lock instead of failing; the
        # longest hold is rebuilding one events index after a bulk load (≈ 35 s at 13.7M).
        cursor.execute("PRAGMA busy_timeout=60000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute(f"PRAGMA cache_size=-{PAGE_CACHE_KIB}")
        cursor.execute("PRAGMA temp_store=MEMORY")
    finally:
        cursor.close()


def make_engine(db_path: Path) -> Engine:
    engine = create_engine(f"sqlite:///{db_path}")
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def _alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def upgrade_db(engine: Engine) -> None:
    """Apply all pending migrations.

    Foreign keys are off while migrations run, because rebuilding a table (the only way
    SQLite changes a key) would otherwise cascade deletes into the tables that reference
    it. The result is checked before they are turned back on.
    """
    config = _alembic_config()
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        try:
            with connection.begin():
                config.attributes["connection"] = connection
                command.upgrade(config, "head")
            problems = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if problems:
                raise RuntimeError(f"migration left {len(problems)} broken reference(s)")
        finally:
            connection.rollback()
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()


def head_revision() -> str | None:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic_config()).get_current_head()
