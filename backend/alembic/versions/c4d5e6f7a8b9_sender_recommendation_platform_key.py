"""add sender_recommendations.platform_key — declared sending platforms

PAIN_POINT_RESOLUTION_PLAN.md Pain 1: a platform the customer declares in
the onboarding wizard (or retroactively) before any DMARC data exists,
tagged with the library key so the setup card and SPF composition can
look it up directly instead of re-matching by source_org name.

Revision ID: c4d5e6f7a8b9
Revises: a9b8c7d6e5f4
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa

revision = 'c4d5e6f7a8b9'
down_revision = 'a9b8c7d6e5f4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sender_recommendations', sa.Column('platform_key', sa.String(50), nullable=True))


def downgrade() -> None:
    op.drop_column('sender_recommendations', 'platform_key')
