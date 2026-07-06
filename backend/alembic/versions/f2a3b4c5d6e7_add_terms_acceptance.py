"""add users.terms_accepted_at + terms_version

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-06-21
"""
from alembic import op
import sqlalchemy as sa

revision = 'f2a3b4c5d6e7'
down_revision = 'e1f2a3b4c5d6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('terms_version', sa.String(20), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'terms_version')
    op.drop_column('users', 'terms_accepted_at')
