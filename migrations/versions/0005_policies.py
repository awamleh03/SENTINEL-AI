"""policies: per-site policy engine (policies + path rules)

Phase 4 (policy engine):
  * create `policies` — an independent rule set for exactly one site, running in
    'monitor' (observe only) or 'block' mode. New policies default to 'monitor';
    blocking is never enabled implicitly.
  * create `policy_rules` — path-matching rules (`prefix` / `exact` / `contains`)
    with a recommended action ('allow' / 'monitor' / 'block') and a priority.
    Higher priority is evaluated first; the winning rule is recorded on the
    security event (`rule_id`).

No existing tables are altered.

Revision ID: 0005_policies
Revises: 0004_notifications
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0005_policies'
down_revision = '0004_notifications'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'policies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('mode', sa.String(length=20), nullable=False, server_default='monitor'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_policies_user_id', 'policies', ['user_id'])
    op.create_index('ix_policies_site_id', 'policies', ['site_id'])
    op.create_index('ix_policies_created_at', 'policies', ['created_at'])

    op.create_table(
        'policy_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('policy_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=120), nullable=False),
        sa.Column('match_type', sa.String(length=20), nullable=False, server_default='prefix'),
        sa.Column('path_pattern', sa.String(length=500), nullable=False),
        sa.Column('action', sa.String(length=20), nullable=False, server_default='monitor'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_policy_rules_policy_id', 'policy_rules', ['policy_id'])
    op.create_index('ix_policy_rules_user_id', 'policy_rules', ['user_id'])
    op.create_index('ix_policy_rules_priority', 'policy_rules', ['priority'])
    op.create_index('ix_policy_rules_created_at', 'policy_rules', ['created_at'])


def downgrade():
    op.drop_index('ix_policy_rules_created_at', table_name='policy_rules')
    op.drop_index('ix_policy_rules_priority', table_name='policy_rules')
    op.drop_index('ix_policy_rules_user_id', table_name='policy_rules')
    op.drop_index('ix_policy_rules_policy_id', table_name='policy_rules')
    op.drop_table('policy_rules')

    op.drop_index('ix_policies_created_at', table_name='policies')
    op.drop_index('ix_policies_site_id', table_name='policies')
    op.drop_index('ix_policies_user_id', table_name='policies')
    op.drop_table('policies')
