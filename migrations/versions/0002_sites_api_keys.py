"""sites and api_keys + site_id columns on scans/alerts

Phase 1 (multi-tenant foundation):
  * create `sites` (a monitored website owned by exactly one account)
  * create `api_keys` (stores only a SHA-256 hash of the secret)
  * add a nullable `site_id` foreign key to `scans` and `alerts`

Revision ID: 0002_sites_api_keys
Revises: 0001_baseline
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0002_sites_api_keys'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'sites',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sites_user_id', 'sites', ['user_id'])
    op.create_index('ix_sites_created_at', 'sites', ['created_at'])

    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('key_prefix', sa.String(length=16), nullable=False),
        sa.Column('key_hash', sa.String(length=128), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('rotated_from_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['rotated_from_id'], ['api_keys.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_api_keys_site_id', 'api_keys', ['site_id'])
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'])
    op.create_index('ix_api_keys_key_prefix', 'api_keys', ['key_prefix'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True)
    op.create_index('ix_api_keys_created_at', 'api_keys', ['created_at'])

    op.add_column('scans', sa.Column('site_id', sa.Integer(), nullable=True))
    op.create_index('ix_scans_site_id', 'scans', ['site_id'])

    op.add_column('alerts', sa.Column('site_id', sa.Integer(), nullable=True))
    op.create_index('ix_alerts_site_id', 'alerts', ['site_id'])


def downgrade():
    op.drop_index('ix_alerts_site_id', table_name='alerts')
    op.drop_column('alerts', 'site_id')

    op.drop_index('ix_scans_site_id', table_name='scans')
    op.drop_column('scans', 'site_id')

    op.drop_index('ix_api_keys_created_at', table_name='api_keys')
    op.drop_index('ix_api_keys_key_hash', table_name='api_keys')
    op.drop_index('ix_api_keys_key_prefix', table_name='api_keys')
    op.drop_index('ix_api_keys_user_id', table_name='api_keys')
    op.drop_index('ix_api_keys_site_id', table_name='api_keys')
    op.drop_table('api_keys')

    op.drop_index('ix_sites_created_at', table_name='sites')
    op.drop_index('ix_sites_user_id', table_name='sites')
    op.drop_table('sites')
