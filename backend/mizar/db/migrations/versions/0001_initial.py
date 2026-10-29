"""Initial schema: cases and jobs.

Revision ID: 0001
Revises:
Create Date: 2026-10-29
"""

import sqlalchemy as sa
from alembic import op

from mizar.db.types import UTCDateTime

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("case_id", sa.String(40), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("reference", sa.String(200)),
        sa.Column("analyst_name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("default_timezone_hint", sa.String(64)),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("case_id", name="pk_cases"),
    )
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(40), nullable=False),
        sa.Column("case_id", sa.String(40)),
        sa.Column("job_type", sa.String(40), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("progress", sa.Float, nullable=False),
        sa.Column("progress_message", sa.Text),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("result", sa.JSON),
        sa.Column("error_code", sa.String(64)),
        sa.Column("error_message", sa.Text),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("started_at", UTCDateTime()),
        sa.Column("finished_at", UTCDateTime()),
        sa.Column("heartbeat_at", UTCDateTime()),
        sa.PrimaryKeyConstraint("job_id", name="pk_jobs"),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.case_id"], name="fk_jobs_case_id_cases", ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name="ck_jobs_status",
        ),
        sa.CheckConstraint("progress >= 0 AND progress <= 1", name="ck_jobs_progress"),
    )
    op.create_index("ix_jobs_status_created_at", "jobs", ["status", "created_at"])
    op.create_index("ix_jobs_case_id", "jobs", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_case_id", table_name="jobs")
    op.drop_index("ix_jobs_status_created_at", table_name="jobs")
    op.drop_table("jobs")
    op.drop_table("cases")
