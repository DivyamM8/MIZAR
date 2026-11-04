"""exports

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-04
"""

import sqlalchemy as sa
from alembic import op

from mizar.db.types import UTCDateTime


revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('exports',
    sa.Column('export_id', sa.String(length=40), nullable=False),
    sa.Column('case_id', sa.String(length=40), nullable=False),
    sa.Column('run_id', sa.String(length=40), nullable=False),
    sa.Column('job_id', sa.String(length=40), nullable=True),
    sa.Column('format', sa.String(length=8), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('options', sa.JSON(), nullable=False),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('created_at', UTCDateTime(), nullable=False),
    sa.Column('finished_at', UTCDateTime(), nullable=True),
    sa.Column('file_name', sa.String(length=80), nullable=True),
    sa.Column('media_type', sa.String(length=40), nullable=True),
    sa.Column('size_bytes', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('summary', sa.JSON(), nullable=True),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.CheckConstraint("format IN ('pdf', 'json', 'csv')", name=op.f('ck_exports_format')),
    sa.CheckConstraint("status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name=op.f('ck_exports_status')),
    sa.ForeignKeyConstraint(['case_id'], ['cases.case_id'], name=op.f('fk_exports_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['analysis_runs.run_id'], name=op.f('fk_exports_run_id_analysis_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('export_id', name=op.f('pk_exports'))
    )
    with op.batch_alter_table('exports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_exports_case_id'), ['case_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_exports_run_id_created_at'), ['run_id', 'created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('exports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_exports_run_id_created_at'))
        batch_op.drop_index(batch_op.f('ix_exports_case_id'))

    op.drop_table('exports')
