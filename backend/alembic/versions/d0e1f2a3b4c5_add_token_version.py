"""add users.token_version for JWT revocation

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-06-21
"""
from alembic import op
import sqlalchemy as sa

revision = 'd0e1f2a3b4c5'
down_revision = 'c9d0e1f2a3b4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('token_version', sa.Integer, nullable=False, server_default='0'))


def downgrade() -> None:
    op.drop_column('users', 'token_version')
