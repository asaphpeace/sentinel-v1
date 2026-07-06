"""add users.concepts_seen

PAIN_POINT_RESOLUTION_PLAN.md Pain 2 — Concept Card dismissal tracking.

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'f3a4b5c6d7e8'
down_revision = 'e2f3a4b5c6d7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('concepts_seen', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'))


def downgrade() -> None:
    op.drop_column('users', 'concepts_seen')
