"""add sender_recommendations table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-18
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'sender_recommendations',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('domain_id', UUID(as_uuid=True), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('source_org', sa.String(500), nullable=False),
        sa.Column('source_ip', sa.String(45), nullable=True),
        sa.Column('classification', sa.String(50), nullable=False),
        sa.Column('recommendation', sa.Text, nullable=True),
        sa.Column('dns_fix', sa.Text, nullable=True),
        sa.Column('is_ai', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('dismissed', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('sender_recommendations')
