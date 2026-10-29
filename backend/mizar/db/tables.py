"""Database tables (SQLAlchemy Core).

Each change here needs a matching Alembic migration; tests/test_db.py fails on drift.
Tables for later phases (source files, events, findings, ...) are added with their phase.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)

from mizar.db.types import UTCDateTime

metadata = MetaData(
    naming_convention={
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
        "uq": "uq_%(table_name)s_%(column_0_N_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")

cases = Table(
    "cases",
    metadata,
    Column("case_id", String(40), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("reference", String(200)),
    Column("analyst_name", String(200), nullable=False),
    Column("description", Text),
    Column("default_timezone_hint", String(64)),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("updated_at", UTCDateTime(), nullable=False),
)

jobs = Table(
    "jobs",
    metadata,
    Column("job_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE")),
    Column("job_type", String(40), nullable=False),
    Column("status", String(16), nullable=False),
    Column("progress", Float, nullable=False, default=0.0),
    Column("progress_message", Text),
    Column("payload", JSON, nullable=False),
    Column("result", JSON),
    Column("error_code", String(64)),
    Column("error_message", Text),
    Column("attempts", Integer, nullable=False, default=0),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("started_at", UTCDateTime()),
    Column("finished_at", UTCDateTime()),
    Column("heartbeat_at", UTCDateTime()),
    CheckConstraint(
        "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name="status"
    ),
    CheckConstraint("progress >= 0 AND progress <= 1", name="progress"),
    Index(None, "status", "created_at"),
    Index(None, "case_id"),
)
