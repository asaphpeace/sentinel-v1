"""add_risk_to_dns_records

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-18 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('dns_records', sa.Column('risk_severity', sa.String(20), nullable=True))
    op.add_column('dns_records', sa.Column('risk_explanation', sa.Text(), nullable=True))
    op.add_column('dns_records', sa.Column('risk_action', sa.Text(), nullable=True))
    op.add_column('dns_records', sa.Column('risk_is_ai', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    op.drop_column('dns_records', 'risk_is_ai')
    op.drop_column('dns_records', 'risk_action')
    op.drop_column('dns_records', 'risk_explanation')
    op.drop_column('dns_records', 'risk_severity')
