"""add alerts.action (paired what-to-do) + sender_recommendations.snoozed_until

GUIDED_ONBOARDING_PLAN.md Part 3 #5 (alerts need a paired "what this means" +
"what to do", not one mixed paragraph) and #15 (a "snooze" state between
act-now and dismiss-forever).

Revision ID: a9b8c7d6e5f4
Revises: f2a3b4c5d6e7
Create Date: 2026-06-23
"""
from alembic import op
import sqlalchemy as sa

revision = 'a9b8c7d6e5f4'
down_revision = 'f2a3b4c5d6e7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('action', sa.Text(), nullable=True))
    op.add_column('sender_recommendations', sa.Column('snoozed_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('sender_recommendations', 'snoozed_until')
    op.drop_column('alerts', 'action')
