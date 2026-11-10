"""rate limits: per-site request caps and fixed-window counters

Phase 5 (rate limiting):
  * create `rate_limit_rules` — per-site request caps keyed on the client IP
    ('ip') or the calling API key ('api_key'), with an explicit `limit_count`
    per `window_seconds` and an action ('monitor' / 'block'). New rules default
    to 'monitor'; blocking is never enabled implicitly.
  * create `rate_limit_counters` — fixed-window counters shared through the
    database so the increment stays consistent across multiple app instances.
    Only a one-way hash of the identity is stored. A unique constraint over
    (site_id, scope, key_hash, window_start) makes the atomic bump safe.

No existing tables are altered.

Revision ID: 0006_rate_limits
Revises: 0005_policies
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0006_rate_limits'
down_revision = '0005_policies'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'rate_limit_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('scope', sa.String(length=10), nullable=False, server_default='ip'),
        sa.Column('limit_count', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('window_seconds', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('action', sa.String(length=20), nullable=False, server_default='monitor'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_rate_limit_rules_user_id', 'rate_limit_rules', ['user_id'])
    op.create_index('ix_rate_limit_rules_site_id', 'rate_limit_rules', ['site_id'])
    op.create_index('ix_rate_limit_rules_priority', 'rate_limit_rules', ['priority'])
    op.create_index('ix_rate_limit_rules_created_at', 'rate_limit_rules', ['created_at'])

    op.create_table(
        'rate_limit_counters',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=False),
        sa.Column('scope', sa.String(length=10), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('window_start', sa.DateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('site_id', 'scope', 'key_hash', 'window_start',
                            name='uq_rate_limit_counter'),
    )
    op.create_index('ix_rate_limit_counters_site_id', 'rate_limit_counters', ['site_id'])
    op.create_index('ix_rate_limit_counters_key_hash', 'rate_limit_counters', ['key_hash'])
    op.create_index('ix_rate_limit_counters_window_start', 'rate_limit_counters', ['window_start'])


def downgrade():
    op.drop_index('ix_rate_limit_counters_window_start', table_name='rate_limit_counters')
    op.drop_index('ix_rate_limit_counters_key_hash', table_name='rate_limit_counters')
    op.drop_index('ix_rate_limit_counters_site_id', table_name='rate_limit_counters')
    op.drop_table('rate_limit_counters')

    op.drop_index('ix_rate_limit_rules_created_at', table_name='rate_limit_rules')
    op.drop_index('ix_rate_limit_rules_priority', table_name='rate_limit_rules')
    op.drop_index('ix_rate_limit_rules_site_id', table_name='rate_limit_rules')
    op.drop_index('ix_rate_limit_rules_user_id', table_name='rate_limit_rules')
    op.drop_table('rate_limit_rules')
