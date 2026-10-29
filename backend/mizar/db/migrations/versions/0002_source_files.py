"""Source files and job cancellation.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-29
"""

import sqlalchemy as sa
from alembic import op

from mizar.db.types import UTCDateTime

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.add_column(
            sa.Column("cancel_requested", sa.Boolean, nullable=False, server_default=sa.false())
        )
    op.create_table(
        "source_files",
        sa.Column("source_file_id", sa.String(40), nullable=False),
        sa.Column("case_id", sa.String(40), nullable=False),
        sa.Column("sequence", sa.Integer, nullable=False),
        sa.Column("parent_file_id", sa.String(40)),
        sa.Column("archive_member_path", sa.Text),
        sa.Column("archive_depth", sa.Integer, nullable=False),
        sa.Column("blob_sha256", sa.String(64), nullable=False),
        sa.Column("original_filename", sa.Text, nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("uploaded_by", sa.String(200), nullable=False),
        sa.Column("ingestion_time", UTCDateTime(), nullable=False),
        sa.Column("container_type", sa.String(16)),
        sa.Column("detected_format", sa.String(40)),
        sa.Column("detection_confidence", sa.Float),
        sa.Column("detection_candidates", sa.JSON),
        sa.Column("encoding", sa.String(20)),
        sa.Column("format_override", sa.String(40)),
        sa.Column("timezone_hint", sa.String(64)),
        sa.Column("year_hint", sa.Integer),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("integrity_status", sa.String(20), nullable=False),
        sa.Column("last_verified_at", UTCDateTime()),
        sa.Column("validation_messages", sa.JSON, nullable=False),
        sa.PrimaryKeyConstraint("source_file_id", name="pk_source_files"),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.case_id"],
            name="fk_source_files_case_id_cases",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["parent_file_id"],
            ["source_files.source_file_id"],
            name="fk_source_files_parent_file_id_source_files",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("case_id", "sequence", name="uq_source_files_case_id_sequence"),
        sa.CheckConstraint(
            "status IN ('stored', 'expanding', 'expanded', 'ready', 'unsupported', 'failed')",
            name="ck_source_files_status",
        ),
        sa.CheckConstraint(
            "integrity_status IN ('unverified', 'verified', 'integrity_failed', 'missing')",
            name="ck_source_files_integrity_status",
        ),
        sa.CheckConstraint("length(blob_sha256) = 64", name="ck_source_files_blob_sha256"),
        sa.CheckConstraint("size_bytes >= 0", name="ck_source_files_size_bytes"),
    )
    op.create_index("ix_source_files_case_id", "source_files", ["case_id"])
    op.create_index("ix_source_files_blob_sha256", "source_files", ["blob_sha256"])
    op.create_index("ix_source_files_parent_file_id", "source_files", ["parent_file_id"])


def downgrade() -> None:
    op.drop_table("source_files")
    with op.batch_alter_table("jobs") as batch:
        batch.drop_column("cancel_requested")
