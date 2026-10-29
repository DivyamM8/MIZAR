"""Database tables (SQLAlchemy Core).

Each change here needs a matching Alembic migration; tests/test_db.py fails on drift.
Tables for later phases (source files, events, findings, ...) are added with their phase.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
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
    UniqueConstraint,
    false,
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

# stored: received, awaiting ingest job | expanding: archive being unpacked
# expanded: archive whose members are separate rows | ready: leaf file, format detected
# unsupported: kept as evidence, cannot be processed | failed: ingest error
SOURCE_FILE_STATUSES = ("stored", "expanding", "expanded", "ready", "unsupported", "failed")
INTEGRITY_STATUSES = ("unverified", "verified", "integrity_failed", "missing")

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
    Column("cancel_requested", Boolean, nullable=False, default=False, server_default=false()),
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

source_files = Table(
    "source_files",
    metadata,
    Column("source_file_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    # Per-case display number, in upload/extraction order.
    Column("sequence", Integer, nullable=False),
    Column(
        "parent_file_id",
        String(40),
        ForeignKey("source_files.source_file_id", ondelete="CASCADE"),
    ),
    Column("archive_member_path", Text),
    Column("archive_depth", Integer, nullable=False, default=0),
    Column("blob_sha256", String(64), nullable=False),
    # Stored verbatim as supplied; never used as a filesystem path.
    Column("original_filename", Text, nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("uploaded_by", String(200), nullable=False),
    Column("ingestion_time", UTCDateTime(), nullable=False),
    Column("container_type", String(16)),
    Column("detected_format", String(40)),
    Column("detection_confidence", Float),
    Column("detection_candidates", JSON),
    Column("encoding", String(20)),
    Column("format_override", String(40)),
    Column("timezone_hint", String(64)),
    Column("year_hint", Integer),
    Column("status", String(16), nullable=False),
    Column("integrity_status", String(20), nullable=False),
    Column("last_verified_at", UTCDateTime()),
    # List of {"level": "warning"|"error", "code", "message", "details"}.
    Column("validation_messages", JSON, nullable=False),
    UniqueConstraint("case_id", "sequence"),
    CheckConstraint(
        "status IN ('stored', 'expanding', 'expanded', 'ready', 'unsupported', 'failed')",
        name="status",
    ),
    CheckConstraint(
        "integrity_status IN ('unverified', 'verified', 'integrity_failed', 'missing')",
        name="integrity_status",
    ),
    CheckConstraint("length(blob_sha256) = 64", name="blob_sha256"),
    CheckConstraint("size_bytes >= 0", name="size_bytes"),
    Index(None, "case_id"),
    Index(None, "blob_sha256"),
    Index(None, "parent_file_id"),
)
