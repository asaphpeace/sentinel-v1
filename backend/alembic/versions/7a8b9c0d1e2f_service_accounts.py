"""add service_accounts

Machine identity for other portfolio products (Workspace OS) reading
Sentinel data without a human login - distinct from users, tenant-scoped,
narrow read-only scopes, revoked via a nullable timestamp rather than a
blacklist table.

Revision ID: 7a8b9c0d1e2f
Revises: 62a2bf2771be
Create Date: 2026-07-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '7a8b9c0d1e2f'
down_revision = '62a2bf2771be'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_name", sa.String(length=100), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_service_accounts_tenant_id", "service_accounts", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_service_accounts_tenant_id", table_name="service_accounts")
    op.drop_table("service_accounts")
