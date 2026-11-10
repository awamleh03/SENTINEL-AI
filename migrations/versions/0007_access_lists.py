"""access lists: per-site allow / block entries

Phase 7 (allow & block lists):
  * create `access_list_rules` — per-site entries that match a client IP, a
    CIDR range or a request path prefix, with an explicit `list_type`
    ('allow' / 'block'), an optional `scope` (the protection scopes an allow
    rule exempts — empty by default, so an allow rule never bypasses all
    protections implicitly) and an explicit `mode` ('monitor' / 'block').
    New rules default to 'monitor'; blocking is never enabled implicitly.
    `created_by_user_id` records who performed each change.

No existing tables are altered.

Revision ID: 0007_access_lists
Revises: 0006_rate_limits
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0007_access_lists'
down_revision = '0006_rate_limits'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'access_list_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=False),
        sa.Column('list_type', sa.String(length=10), nullable=False),
        sa.Column('match_type', sa.String(length=10), nullable=False),
        sa.Column('value', sa.String(length=500), nullable=False),
        sa.Column('scope', sa.String(length=120), nullable=False, server_default=''),
        sa.Column('mode', sa.String(length=10), nullable=False, server_default='monitor'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_by_user_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_access_list_rules_user_id', 'access_list_rules', ['user_id'])
    op.create_index('ix_access_list_rules_site_id', 'access_list_rules', ['site_id'])
    op.create_index('ix_access_list_rules_list_type', 'access_list_rules', ['list_type'])
    op.create_index('ix_access_list_rules_priority', 'access_list_rules', ['priority'])
    op.create_index('ix_access_list_rules_created_at', 'access_list_rules', ['created_at'])


def downgrade():
    op.drop_index('ix_access_list_rules_created_at', table_name='access_list_rules')
    op.drop_index('ix_access_list_rules_priority', table_name='access_list_rules')
    op.drop_index('ix_access_list_rules_list_type', table_name='access_list_rules')
    op.drop_index('ix_access_list_rules_site_id', table_name='access_list_rules')
    op.drop_index('ix_access_list_rules_user_id', table_name='access_list_rules')
    op.drop_table('access_list_rules')
