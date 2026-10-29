from datetime import UTC, datetime

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, insert, inspect, select, text
from sqlalchemy.exc import IntegrityError, StatementError

from mizar.db.engine import head_revision
from mizar.db.tables import cases, jobs, metadata


def test_migrations_create_schema_at_head(engine: Engine) -> None:
    assert {"cases", "jobs", "alembic_version"} <= set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == (
            head_revision()
        )


def test_tables_match_migrations(engine: Engine) -> None:
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), metadata)
    assert diff == []


def test_sqlite_pragmas(engine: Engine) -> None:
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def _case_row(**overrides: object) -> dict[str, object]:
    now = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
    row: dict[str, object] = {
        "case_id": "CASE-1",
        "name": "Test",
        "analyst_name": "analyst",
        "created_at": now,
        "updated_at": now,
    }
    row.update(overrides)
    return row


def test_utc_datetime_round_trip(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(insert(cases).values(_case_row()))
        stored = conn.execute(select(cases.c.created_at)).scalar_one()
    assert stored == datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
    assert stored.tzinfo is UTC


def test_naive_datetime_is_rejected_by_column(engine: Engine) -> None:
    with pytest.raises(StatementError, match="naive"), engine.begin() as conn:
        conn.execute(insert(cases).values(_case_row(created_at=datetime(2026, 10, 29))))


def test_job_constraints(engine: Engine) -> None:
    now = datetime(2026, 10, 29, tzinfo=UTC)
    job = {
        "job_id": "JOB-1",
        "job_type": "ingest",
        "status": "queued",
        "progress": 0.0,
        "payload": {},
        "attempts": 0,
        "created_at": now,
    }
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(insert(jobs).values({**job, "status": "bogus"}))
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(insert(jobs).values({**job, "case_id": "CASE-missing"}))
