"""fix leftover unique index on users.email

The previous migration (d4e5f6a7b8c9) dropped the users_email_key unique
CONSTRAINT, but missed a second, separate object: ix_users_email, a unique
INDEX that SQLAlchemy created because the original column declaration had
both unique=True and index=True. That index was still silently enforcing
global email uniqueness, defeating the whole point of the previous
migration (SSO accounts sharing an email across tenants would still have
been rejected by ix_users_email).

Replaces it with a plain non-unique index — email lookups still benefit
from an index, just not a unique one.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-20
"""
from alembic import op

revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute('DROP INDEX IF EXISTS ix_users_email')
    op.create_index('ix_users_email', 'users', ['email'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_users_email', table_name='users')
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
