"""security_events: append-only audit/security event log

Phase 2 (security event log):
  * create `security_events` — one row per event, scoped to a user (and
    optionally a site). Stores the detection `decision` separately from the
    enforced `action_taken`. `details` is sanitized JSON text (no passwords,
    tokens or request content).

Revision ID: 0003_security_events
Revises: 0002_sites_api_keys
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0003_security_events'
down_revision = '0002_sites_api_keys'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('site_id', sa.Integer(), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('threat_type', sa.String(length=80), nullable=True),
        sa.Column('method', sa.String(length=10), nullable=True),
        sa.Column('path', sa.String(length=500), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('decision', sa.String(length=20), nullable=True),
        sa.Column('action_taken', sa.String(length=20), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('rule_id', sa.String(length=120), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_events_user_id', 'security_events', ['user_id'])
    op.create_index('ix_security_events_site_id', 'security_events', ['site_id'])
    op.create_index('ix_security_events_event_type', 'security_events', ['event_type'])
    op.create_index('ix_security_events_threat_type', 'security_events', ['threat_type'])
    op.create_index('ix_security_events_ip_address', 'security_events', ['ip_address'])
    op.create_index('ix_security_events_decision', 'security_events', ['decision'])
    op.create_index('ix_security_events_action_taken', 'security_events', ['action_taken'])
    op.create_index('ix_security_events_rule_id', 'security_events', ['rule_id'])
    op.create_index('ix_security_events_created_at', 'security_events', ['created_at'])


def downgrade():
    op.drop_index('ix_security_events_created_at', table_name='security_events')
    op.drop_index('ix_security_events_rule_id', table_name='security_events')
    op.drop_index('ix_security_events_action_taken', table_name='security_events')
    op.drop_index('ix_security_events_decision', table_name='security_events')
    op.drop_index('ix_security_events_ip_address', table_name='security_events')
    op.drop_index('ix_security_events_threat_type', table_name='security_events')
    op.drop_index('ix_security_events_event_type', table_name='security_events')
    op.drop_index('ix_security_events_site_id', table_name='security_events')
    op.drop_index('ix_security_events_user_id', table_name='security_events')
    op.drop_table('security_events')
