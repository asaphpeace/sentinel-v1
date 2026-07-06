"""email verification: users.email_verified + email_verification_tokens

email_verified defaults to true at the DB level — every existing user and
every other user-creation path (invite accept, MSP direct-create) already
proves email ownership some other way (received the invite link, or was
created by a trusted admin), so they're grandfathered in as verified.
register() is the one path that explicitly sets this to False, since that's
the only signup path where the email address is unproven at creation time.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-06-21
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = 'c9d0e1f2a3b4'
down_revision = 'b8c9d0e1f2a3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('email_verified', sa.Boolean, nullable=False, server_default='true'),
    )

    op.create_table(
        'email_verification_tokens',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('token', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('used', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('email_verification_tokens')
    op.drop_column('users', 'email_verified')
