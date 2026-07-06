"""add_narrative_to_snapshots

Revision ID: a1b2c3d4e5f6
Revises: 58b5625d8b68
Create Date: 2026-06-18 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'c31e0f2267d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('sentinel_snapshots', sa.Column('narrative_summary', sa.Text(), nullable=True))
    op.add_column('sentinel_snapshots', sa.Column('narrative_threats', sa.Text(), nullable=True))
    op.add_column('sentinel_snapshots', sa.Column('narrative_actions', sa.Text(), nullable=True))
    op.add_column('sentinel_snapshots', sa.Column('narrative_generated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('sentinel_snapshots', sa.Column('narrative_is_ai', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    op.drop_column('sentinel_snapshots', 'narrative_is_ai')
    op.drop_column('sentinel_snapshots', 'narrative_generated_at')
    op.drop_column('sentinel_snapshots', 'narrative_actions')
    op.drop_column('sentinel_snapshots', 'narrative_threats')
    op.drop_column('sentinel_snapshots', 'narrative_summary')
