"""sso-ready user identity: per-tenant email uniqueness + auth_method

Replaces the old global unique(email) with:
  - uq_users_tenant_email: unique (tenant_id, email) — always enforced,
    so one workspace can never have two accounts answering to the same address.
  - ix_users_email_password_unique: a partial unique index on email,
    enforced only WHERE auth_method = 'password' — this is what blocks
    duplicate self-registration across tenants, while leaving SSO accounts
    free to share an email across tenants (an MSP contractor's corporate
    email can legitimately be an SSO identity in more than one client
    tenant — see recommendation_engine design discussion).

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-06-20
"""
from alembic import op
import sqlalchemy as sa

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('auth_method', sa.String(20), nullable=False, server_default='password'),
    )
    op.alter_column('users', 'hashed_password', existing_type=sa.String(200), nullable=True)

    # Drop the old global unique constraint on email (name as created by SQLAlchemy's
    # unique=True on a single column — Postgres default naming convention).
    op.execute('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key')

    op.create_unique_constraint('uq_users_tenant_email', 'users', ['tenant_id', 'email'])

    op.execute(
        'CREATE UNIQUE INDEX ix_users_email_password_unique '
        "ON users (email) WHERE auth_method = 'password'"
    )


def downgrade() -> None:
    op.execute('DROP INDEX IF EXISTS ix_users_email_password_unique')
    op.drop_constraint('uq_users_tenant_email', 'users', type_='unique')
    op.alter_column('users', 'hashed_password', existing_type=sa.String(200), nullable=False)
    op.drop_column('users', 'auth_method')
    op.create_unique_constraint('users_email_key', 'users', ['email'])
