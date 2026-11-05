"""event id as a unique index, not the primary key

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-05

SQLite cannot change a primary key in place, so the table is rebuilt. upgrade_db runs
migrations with foreign keys off, so dropping the old table does not cascade to the
tables that reference events (raw_records, event_group_members).
"""

from alembic import op


revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

_COLUMNS = """
	event_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(40) NOT NULL,
	source_file_id VARCHAR(40) NOT NULL,
	parse_result_id VARCHAR(40) NOT NULL,
	source_type VARCHAR(30) NOT NULL,
	parser_name VARCHAR(60) NOT NULL,
	record_index INTEGER NOT NULL,
	original_record_reference JSON NOT NULL,
	record_hash VARCHAR(64) NOT NULL,
	timestamp_original TEXT,
	timestamp_utc VARCHAR(27),
	timestamp_precision VARCHAR(2),
	timezone_assumption VARCHAR(80) NOT NULL,
	hostname TEXT,
	username TEXT,
	user_domain TEXT,
	source_ip VARCHAR(45),
	destination_ip VARCHAR(45),
	source_port INTEGER,
	destination_port INTEGER,
	protocol VARCHAR(20),
	event_category VARCHAR(30),
	event_type VARCHAR(60),
	event_outcome VARCHAR(10),
	event_code VARCHAR(40),
	process_name TEXT,
	process_id INTEGER,
	session_id TEXT,
	message TEXT,
	extra JSON NOT NULL,
	parsing_status VARCHAR(10) NOT NULL,
	parse_warnings JSON NOT NULL,"""
_CONSTRAINTS = """
	CONSTRAINT fk_events_case_id_cases FOREIGN KEY(case_id) REFERENCES cases (case_id) ON DELETE CASCADE,
	CONSTRAINT fk_events_parse_result_id_parse_results FOREIGN KEY(parse_result_id) REFERENCES parse_results (parse_result_id) ON DELETE CASCADE,
	CONSTRAINT fk_events_source_file_id_source_files FOREIGN KEY(source_file_id) REFERENCES source_files (source_file_id) ON DELETE CASCADE,
	CONSTRAINT uq_events_source_file_id_record_index UNIQUE (source_file_id, record_index)"""
_INDEXES = [
    "CREATE INDEX ix_events_case_id_timestamp_utc_source_file_id_record_index ON events (case_id, timestamp_utc, source_file_id, record_index)",
    "CREATE INDEX ix_events_destination_ip ON events (destination_ip)",
    "CREATE INDEX ix_events_event_code ON events (event_code)",
    "CREATE INDEX ix_events_event_type ON events (event_type)",
    "CREATE INDEX ix_events_hostname ON events (hostname)",
    "CREATE INDEX ix_events_record_hash ON events (record_hash)",
    "CREATE INDEX ix_events_session_id ON events (session_id)",
    "CREATE INDEX ix_events_source_ip ON events (source_ip)",
    "CREATE INDEX ix_events_username ON events (username)",
]


def _rebuild(primary_key: bool) -> None:
    key = "\n\tCONSTRAINT pk_events PRIMARY KEY (event_id)," if primary_key else ""
    op.execute(f"CREATE TABLE _events_new ({_COLUMNS}{key}{_CONSTRAINTS}\n)")
    op.execute("INSERT INTO _events_new SELECT * FROM events")
    op.execute("DROP TABLE events")
    op.execute("ALTER TABLE _events_new RENAME TO events")
    for statement in _INDEXES:
        op.execute(statement)


def upgrade() -> None:
    _rebuild(primary_key=False)
    op.execute("CREATE UNIQUE INDEX ix_events_event_id ON events (event_id)")


def downgrade() -> None:
    _rebuild(primary_key=True)
