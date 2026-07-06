"""add tenants.report_schedule + last_report_sent_at

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-06-21
"""
from alembic import op
import sqlalchemy as sa

revision = 'e1f2a3b4c5d6'
down_revision = 'd0e1f2a3b4c5'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('tenants', sa.Column('report_schedule', sa.String(20), nullable=False, server_default='off'))
    op.add_column('tenants', sa.Column('last_report_sent_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('tenants', 'last_report_sent_at')
    op.drop_column('tenants', 'report_schedule')
