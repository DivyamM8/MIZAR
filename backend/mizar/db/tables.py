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
    LargeBinary,
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

PARSE_RESULT_STATUSES = ("running", "succeeded", "succeeded_with_warnings", "failed", "cancelled")

parse_results = Table(
    "parse_results",
    metadata,
    Column("parse_result_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column(
        "source_file_id",
        String(40),
        ForeignKey("source_files.source_file_id", ondelete="CASCADE"),
        nullable=False,
    ),
    # Only the latest parse of a file is current; earlier results are kept for provenance.
    Column("is_current", Boolean, nullable=False),
    Column("format_id", String(40), nullable=False),
    Column("parser_name", String(60), nullable=False),
    Column("parser_version", String(20), nullable=False),
    # Per-parse constants of every event it produced (kept here, not repeated per row).
    Column("schema_version", String(16), nullable=False),
    # Hints in effect for this parse (they change timestamp_utc).
    Column("timezone_hint", String(64)),
    Column("year_hint", Integer),
    Column("status", String(30), nullable=False),
    Column("started_at", UTCDateTime(), nullable=False),
    Column("finished_at", UTCDateTime()),
    Column("records_total", Integer, nullable=False, default=0),
    Column("records_parsed", Integer, nullable=False, default=0),
    Column("records_partial", Integer, nullable=False, default=0),
    Column("records_unparsed", Integer, nullable=False, default=0),
    # Counts per event warning code, plus file-level problems such as unreadable EVTX chunks.
    Column("warnings_by_code", JSON, nullable=False),
    Column("file_problems", JSON, nullable=False),
    Column("first_timestamp_utc", UTCDateTime()),
    Column("last_timestamp_utc", UTCDateTime()),
    Column("error_code", String(64)),
    Column("error_message", Text),
    CheckConstraint(
        "status IN ('running', 'succeeded', 'succeeded_with_warnings', 'failed', 'cancelled')",
        name="status",
    ),
    Index(None, "source_file_id", "is_current"),
    Index(None, "case_id"),
)

# schema_version, parser_version and ingestion_time are per parse: the API joins them
# from parse_results (ingestion_time = parse_results.started_at).
# The event ID has a unique index rather than being the primary key, so a large file can
# be loaded without it and the index rebuilt once (DESIGN.md D48, mizar/db/bulk.py).
events = Table(
    "events",
    metadata,
    Column("event_id", String(36), nullable=False),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column(
        "source_file_id",
        String(40),
        ForeignKey("source_files.source_file_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "parse_result_id",
        String(40),
        ForeignKey("parse_results.parse_result_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("source_type", String(30), nullable=False),
    Column("parser_name", String(60), nullable=False),
    Column("record_index", Integer, nullable=False),
    Column("original_record_reference", JSON, nullable=False),
    Column("record_hash", String(64), nullable=False),
    Column("timestamp_original", Text),
    Column("timestamp_utc", UTCDateTime()),
    Column("timestamp_precision", String(2)),
    Column("timezone_assumption", String(80), nullable=False),
    Column("hostname", Text),
    Column("username", Text),
    Column("user_domain", Text),
    Column("source_ip", String(45)),
    Column("destination_ip", String(45)),
    Column("source_port", Integer),
    Column("destination_port", Integer),
    Column("protocol", String(20)),
    Column("event_category", String(30)),
    Column("event_type", String(60)),
    Column("event_outcome", String(10)),
    Column("event_code", String(40)),
    Column("process_name", Text),
    Column("process_id", Integer),
    Column("session_id", Text),
    Column("message", Text),
    Column("extra", JSON, nullable=False),
    Column("parsing_status", String(10), nullable=False),
    Column("parse_warnings", JSON, nullable=False),
    UniqueConstraint("source_file_id", "record_index"),
    # Single-column filter indexes stay small; planner statistics (PRAGMA optimize after
    # each parse) let SQLite prefer them over the case_id index for selective filters.
    # Covers the timeline order exactly, so keyset pages never sort (DESIGN.md §10.3).
    Index(None, "case_id", "timestamp_utc", "source_file_id", "record_index"),
    Index(None, "source_ip"),
    Index(None, "destination_ip"),
    Index(None, "username"),
    Index(None, "hostname"),
    Index(None, "session_id"),
    Index(None, "event_type"),
    Index(None, "event_code"),
    Index(None, "record_hash"),
    Index(None, "event_id", unique=True),
)

# Copies of original record bytes, only for records whose locator cannot be read back
# cheaply from the evidence file (EVTX renderings, XML/JSON/CSV items, UTF-16 text).
# Line-framed UTF-8 records are read from the evidence file by byte offset and
# verified against record_hash instead (DESIGN.md D7).
raw_records = Table(
    "raw_records",
    metadata,
    Column(
        "event_id",
        String(36),
        ForeignKey("events.event_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    # Text encoding of the bytes, or "binary-rendering" for EVTX (see DESIGN.md §7.2).
    Column("encoding", String(30), nullable=False),
    Column("compression", String(8), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("data", LargeBinary, nullable=False),
    CheckConstraint("compression IN ('none', 'zlib')", name="compression"),
)

EVENT_GROUP_TYPES = ("duplicate", "session", "chain")

event_groups = Table(
    "event_groups",
    metadata,
    Column("group_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column("group_type", String(16), nullable=False),
    Column("group_key", Text, nullable=False),
    Column("member_count", Integer, nullable=False),
    # Session groups: start/end, accounts, addresses, event types (DESIGN.md §10.2).
    Column("summary", JSON),
    Column("first_utc", UTCDateTime()),
    Column("last_utc", UTCDateTime()),
    Column("created_at", UTCDateTime(), nullable=False),
    CheckConstraint("group_type IN ('duplicate', 'session', 'chain')", name="group_type"),
    Index(None, "case_id", "group_type"),
)

event_group_members = Table(
    "event_group_members",
    metadata,
    Column(
        "group_id",
        String(40),
        ForeignKey("event_groups.group_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "event_id",
        String(36),
        ForeignKey("events.event_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index(None, "event_id"),
)

RUN_STATUSES = ("queued", "running", "succeeded", "succeeded_with_errors", "failed", "cancelled")
FINDING_STATUSES = ("open", "investigating", "confirmed", "false_positive", "resolved")

analysis_runs = Table(
    "analysis_runs",
    metadata,
    Column("run_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column("job_id", String(40)),
    Column("status", String(24), nullable=False),
    Column("triggered_by", String(200), nullable=False),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("started_at", UTCDateTime()),
    Column("finished_at", UTCDateTime()),
    # Parameter overrides requested for this run (validated against the rule set).
    Column("overrides", JSON, nullable=False),
    # DESIGN.md §12.1: inputs, rules, config, versions.
    Column("manifest", JSON),
    Column("manifest_sha256", String(64)),
    # Hash of everything that determines the findings (no run ID or timestamps):
    # two runs with the same value must produce the same findings.
    Column("inputs_fingerprint", String(64)),
    Column("results", JSON),
    Column("error_code", String(64)),
    Column("error_message", Text),
    CheckConstraint(
        "status IN ('queued', 'running', 'succeeded', 'succeeded_with_errors', 'failed', "
        "'cancelled')",
        name="status",
    ),
    Index(None, "case_id", "created_at"),
)

findings = Table(
    "findings",
    metadata,
    Column("finding_id", String(60), primary_key=True),
    Column(
        "run_id", String(40), ForeignKey("analysis_runs.run_id", ondelete="CASCADE"), nullable=False
    ),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("rule_id", String(20), nullable=False),
    Column("rule_version", String(20), nullable=False),
    Column("title", Text, nullable=False),
    Column("description", Text, nullable=False),
    Column("severity", String(16), nullable=False),
    Column("severity_rationale", JSON, nullable=False),
    Column("confidence", String(8), nullable=False),
    Column("confidence_rationale", JSON, nullable=False),
    Column("evidence_strength", String(16), nullable=False),
    Column("attack_techniques", JSON, nullable=False),
    Column("first_observed_utc", UTCDateTime()),
    Column("last_observed_utc", UTCDateTime()),
    Column("entities", JSON, nullable=False),
    Column("observed_evidence", JSON, nullable=False),
    Column("interpretation", Text, nullable=False),
    Column("alternative_explanations", JSON, nullable=False),
    Column("verification_steps", JSON, nullable=False),
    Column("source_files", JSON, nullable=False),
    Column("related_finding_ids", JSON, nullable=False),
    Column("event_count", Integer, nullable=False),
    Column("status", String(16), nullable=False),
    Column("analyst_notes", Text),
    Column("status_carried_from", String(60)),
    Column("updated_by", String(200)),
    Column("updated_at", UTCDateTime()),
    CheckConstraint(
        "severity IN ('informational', 'low', 'medium', 'high', 'critical')", name="severity"
    ),
    CheckConstraint("confidence IN ('low', 'medium', 'high')", name="confidence"),
    CheckConstraint(
        "evidence_strength IN ('direct', 'corroborated', 'circumstantial', 'inferred')",
        name="evidence_strength",
    ),
    CheckConstraint(
        "status IN ('open', 'investigating', 'confirmed', 'false_positive', 'resolved')",
        name="status",
    ),
    Index(None, "run_id"),
    Index(None, "case_id", "fingerprint"),
)

# Evidence links. No foreign key to events: a later re-parse replaces events (usually
# with the same IDs), and an old run's links must survive that; missing events are
# reported as such.
finding_events = Table(
    "finding_events",
    metadata,
    Column(
        "finding_id",
        String(60),
        ForeignKey("findings.finding_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("event_id", String(36), primary_key=True),
    Column("role", String(30), nullable=False),
    Column("position", Integer, nullable=False),
    Index(None, "event_id"),
)

ENTITY_TYPES = ("host", "user", "ip")

# Rebuilt by the case index job after parsing (DESIGN.md §10.1).
entities = Table(
    "entities",
    metadata,
    Column(
        "case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), primary_key=True
    ),
    Column("entity_type", String(8), primary_key=True),
    Column("value", Text, primary_key=True),
    Column("event_count", Integer, nullable=False),
    # Records without a reliable UTC time are counted but have no place in time.
    Column("unplaced_count", Integer, nullable=False),
    Column("first_seen_utc", UTCDateTime()),
    Column("last_seen_utc", UTCDateTime()),
    # For IPs: how often the address appears as source and as destination.
    Column("as_source", Integer),
    Column("as_destination", Integer),
    Column("source_file_ids", JSON, nullable=False),
    CheckConstraint("entity_type IN ('host', 'user', 'ip')", name="entity_type"),
    Index(None, "case_id", "entity_type", "event_count"),
)

# Only relationships the source itself documents (Sysmon ProcessGuid). Links by shared
# IP/user/time are computed on request and never stored or presented as causal.
event_links = Table(
    "event_links",
    metadata,
    Column("link_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column("from_event_id", String(36), nullable=False),
    Column("to_event_id", String(36), nullable=False),
    Column("link_type", String(30), nullable=False),
    Column("basis", JSON, nullable=False),
    CheckConstraint("link_type IN ('parent_process_of', 'process_performed')", name="link_type"),
    Index(None, "case_id"),
    Index(None, "from_event_id"),
    Index(None, "to_event_id"),
)

EXPORT_FORMATS = ("pdf", "json", "csv")
EXPORT_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")

exports = Table(
    "exports",
    metadata,
    Column("export_id", String(40), primary_key=True),
    Column("case_id", String(40), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
    Column(
        "run_id", String(40), ForeignKey("analysis_runs.run_id", ondelete="CASCADE"), nullable=False
    ),
    Column("job_id", String(40)),
    Column("format", String(8), nullable=False),
    Column("status", String(16), nullable=False),
    # Filters and presentation choices (DESIGN.md §13): statuses, min severity, marking, ...
    Column("options", JSON, nullable=False),
    Column("requested_by", String(200), nullable=False),
    Column("created_at", UTCDateTime(), nullable=False),
    Column("finished_at", UTCDateTime()),
    # Set when the file is complete: name inside exports/<case_id>/, size and SHA-256.
    Column("file_name", String(80)),
    Column("media_type", String(40)),
    Column("size_bytes", Integer),
    Column("sha256", String(64)),
    # Counts of what the export contains, for the list view.
    Column("summary", JSON),
    Column("error_code", String(64)),
    Column("error_message", Text),
    CheckConstraint("format IN ('pdf', 'json', 'csv')", name="format"),
    CheckConstraint(
        "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name="status"
    ),
    Index(None, "run_id", "created_at"),
    Index(None, "case_id"),
)
