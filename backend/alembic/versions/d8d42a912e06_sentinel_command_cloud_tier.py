"""sentinel command cloud tier

Tier 0 (Cloud Posture Scanning) foundation tables, plus Engagement and
Finding which are shared across every future Sentinel Command tier.
Autogenerate also flagged unrelated pre-existing drift on
dmarc_reports/tls_reports/users/service_accounts (partial-index and
nullability differences that predate this change) — deliberately excluded
here, out of scope for this migration.

Revision ID: d8d42a912e06
Revises: 7a8b9c0d1e2f
Create Date: 2026-07-03
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'd8d42a912e06'
down_revision = '7a8b9c0d1e2f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('cloud_account_connections',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('provider', sa.String(length=20), nullable=False),
    sa.Column('role_arn', sa.String(length=2048), nullable=True),
    sa.Column('external_id', sa.String(length=128), nullable=True),
    sa.Column('azure_tenant_id', sa.String(length=64), nullable=True),
    sa.Column('azure_client_id', sa.String(length=64), nullable=True),
    sa.Column('azure_subscription_id', sa.String(length=64), nullable=True),
    sa.Column('gcp_project_id', sa.String(length=64), nullable=True),
    sa.Column('gcp_service_account_email', sa.String(length=320), nullable=True),
    sa.Column('encrypted_credentials', sa.String(), nullable=True),
    sa.Column('uses_federation', sa.Boolean(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('connected_by_user_id', sa.UUID(), nullable=True),
    sa.Column('connected_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['connected_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_account_connections_tenant_id'), 'cloud_account_connections', ['tenant_id'], unique=False)

    op.create_table('engagements',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('domain_id', sa.UUID(), nullable=True),
    sa.Column('tier', sa.String(length=20), nullable=False),
    sa.Column('scope', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('approved_by_user_id', sa.UUID(), nullable=True),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('roe_signature_request_id', sa.String(length=200), nullable=True),
    sa.Column('roe_doc_url', sa.String(length=500), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['approved_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_engagements_domain_id'), 'engagements', ['domain_id'], unique=False)
    op.create_index(op.f('ix_engagements_tenant_id'), 'engagements', ['tenant_id'], unique=False)

    op.create_table('cloud_assets',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('cloud_account_connection_id', sa.UUID(), nullable=False),
    sa.Column('resource_type', sa.String(length=50), nullable=False),
    sa.Column('resource_id', sa.String(length=2048), nullable=False),
    sa.Column('region', sa.String(length=50), nullable=True),
    sa.Column('resource_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['cloud_account_connection_id'], ['cloud_account_connections.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_assets_cloud_account_connection_id'), 'cloud_assets', ['cloud_account_connection_id'], unique=False)
    op.create_index('ix_cloud_assets_connection_type', 'cloud_assets', ['cloud_account_connection_id', 'resource_type'], unique=False)
    op.create_index(op.f('ix_cloud_assets_tenant_id'), 'cloud_assets', ['tenant_id'], unique=False)

    op.create_table('cloud_priv_esc_paths',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=False),
    sa.Column('cloud_account_connection_id', sa.UUID(), nullable=False),
    sa.Column('source_principal_arn', sa.String(length=2048), nullable=False),
    sa.Column('target_principal_arn', sa.String(length=2048), nullable=False),
    sa.Column('technique_chain', postgresql.ARRAY(sa.String()), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['cloud_account_connection_id'], ['cloud_account_connections.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_priv_esc_paths_cloud_account_connection_id'), 'cloud_priv_esc_paths', ['cloud_account_connection_id'], unique=False)
    op.create_index(op.f('ix_cloud_priv_esc_paths_engagement_id'), 'cloud_priv_esc_paths', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_cloud_priv_esc_paths_tenant_id'), 'cloud_priv_esc_paths', ['tenant_id'], unique=False)

    op.create_table('findings',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('engagement_id', sa.UUID(), nullable=False),
    sa.Column('asset_id', sa.UUID(), nullable=True),
    sa.Column('tier', sa.String(length=20), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('check_id', sa.String(length=200), nullable=True),
    sa.Column('detail', sa.String(), nullable=True),
    sa.Column('remediation_guidance', sa.String(), nullable=True),
    sa.Column('proof_ref', sa.String(length=200), nullable=True),
    sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['cloud_assets.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_engagement_id'), 'findings', ['engagement_id'], unique=False)
    op.create_index('ix_findings_engagement_status', 'findings', ['engagement_id', 'status'], unique=False)
    op.create_index(op.f('ix_findings_tenant_id'), 'findings', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_findings_tenant_id'), table_name='findings')
    op.drop_index('ix_findings_engagement_status', table_name='findings')
    op.drop_index(op.f('ix_findings_engagement_id'), table_name='findings')
    op.drop_table('findings')

    op.drop_index(op.f('ix_cloud_priv_esc_paths_tenant_id'), table_name='cloud_priv_esc_paths')
    op.drop_index(op.f('ix_cloud_priv_esc_paths_engagement_id'), table_name='cloud_priv_esc_paths')
    op.drop_index(op.f('ix_cloud_priv_esc_paths_cloud_account_connection_id'), table_name='cloud_priv_esc_paths')
    op.drop_table('cloud_priv_esc_paths')

    op.drop_index(op.f('ix_cloud_assets_tenant_id'), table_name='cloud_assets')
    op.drop_index('ix_cloud_assets_connection_type', table_name='cloud_assets')
    op.drop_index(op.f('ix_cloud_assets_cloud_account_connection_id'), table_name='cloud_assets')
    op.drop_table('cloud_assets')

    op.drop_index(op.f('ix_engagements_tenant_id'), table_name='engagements')
    op.drop_index(op.f('ix_engagements_domain_id'), table_name='engagements')
    op.drop_table('engagements')

    op.drop_index(op.f('ix_cloud_account_connections_tenant_id'), table_name='cloud_account_connections')
    op.drop_table('cloud_account_connections')
