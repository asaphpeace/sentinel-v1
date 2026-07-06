"""add ssl_certs.error_kind

Differentiates MTA-STS/MX probe failure modes (no DNS vs connection
refused/timeout vs untrusted TLS chain vs other) instead of collapsing
everything into one opaque probe_error string.

Revision ID: 62a2bf2771be
Revises: f3a4b5c6d7e8
Create Date: 2026-06-24
"""
from alembic import op
import sqlalchemy as sa

revision = '62a2bf2771be'
down_revision = 'f3a4b5c6d7e8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('ssl_certs', sa.Column('error_kind', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('ssl_certs', 'error_kind')
