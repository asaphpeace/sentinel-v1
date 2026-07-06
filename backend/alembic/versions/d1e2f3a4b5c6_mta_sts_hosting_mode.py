"""add domains.mta_sts_hosting_mode

PAIN_POINT_RESOLUTION_PLAN.md Pain 5: "self" (today's only option, the
customer hosts mta-sts.<domain> themselves) vs "managed" (Sentinel serves
the policy dynamically — the customer just publishes one CNAME).

Revision ID: d1e2f3a4b5c6
Revises: c4d5e6f7a8b9
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa

revision = 'd1e2f3a4b5c6'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('domains', sa.Column('mta_sts_hosting_mode', sa.String(10), nullable=False, server_default='self'))


def downgrade() -> None:
    op.drop_column('domains', 'mta_sts_hosting_mode')
