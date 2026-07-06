"""add audit_log_entries table

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-06-20
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'audit_log_entries',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('actor_user_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('actor_email', sa.String(320), nullable=True),
        sa.Column('action', sa.String(100), nullable=False, index=True),
        sa.Column('target_type', sa.String(50), nullable=True),
        sa.Column('target_id', sa.String(100), nullable=True),
        sa.Column('target_label', sa.String(300), nullable=True),
        sa.Column('before', JSONB, nullable=True),
        sa.Column('after', JSONB, nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_audit_log_tenant_created', 'audit_log_entries', ['tenant_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_audit_log_tenant_created', table_name='audit_log_entries')
    op.drop_table('audit_log_entries')
