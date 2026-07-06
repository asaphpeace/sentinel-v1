"""add subdomain_dispositions table

PAIN_POINT_RESOLUTION_PLAN.md Pain 6: every discovered, mail-sending
subdomain must have an explicit disposition (monitor/exclude/inherited_sp)
before the parent domain can be considered enforcement-ready.

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'e2f3a4b5c6d7'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'subdomain_dispositions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('domain_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('hostname', sa.String(253), nullable=False),
        sa.Column('disposition', sa.String(20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('domain_id', 'hostname', name='uq_subdomain_disposition_domain_hostname'),
    )


def downgrade() -> None:
    op.drop_table('subdomain_dispositions')
