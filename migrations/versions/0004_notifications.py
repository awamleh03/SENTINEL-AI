"""notifications: channels, delivery log and aggregation ledger

Phase 3 (notifications):
  * create `notification_channels` — per-account (optionally per-site) channel
    config. Secrets live in `config` (JSON text) on the server and are never
    returned to the browser.
  * create `notification_log` — delivery/audit trail per attempt.
  * create `notification_aggregates` — collapses repeated identical events
    within a window so users are not flooded.

No existing tables are altered.

Revision ID: 0004_notifications
Revises: 0003_security_events
Create Date: 2026-11-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0004_notifications'
down_revision = '0003_security_events'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'notification_channels',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=True),
        sa.Column('channel_type', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('config', sa.Text(), nullable=True),
        sa.Column('min_severity', sa.String(length=10), nullable=False, server_default='medium'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('last_tested_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_notification_channels_user_id', 'notification_channels', ['user_id'])
    op.create_index('ix_notification_channels_site_id', 'notification_channels', ['site_id'])
    op.create_index('ix_notification_channels_channel_type', 'notification_channels', ['channel_type'])
    op.create_index('ix_notification_channels_created_at', 'notification_channels', ['created_at'])

    op.create_table(
        'notification_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('site_id', sa.Integer(), nullable=True),
        sa.Column('channel_id', sa.Integer(), nullable=True),
        sa.Column('event_id', sa.Integer(), nullable=True),
        sa.Column('channel_type', sa.String(length=20), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('subject', sa.String(length=200), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('dedup_key', sa.String(length=200), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id']),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_notification_log_user_id', 'notification_log', ['user_id'])
    op.create_index('ix_notification_log_site_id', 'notification_log', ['site_id'])
    op.create_index('ix_notification_log_channel_id', 'notification_log', ['channel_id'])
    op.create_index('ix_notification_log_event_id', 'notification_log', ['event_id'])
    op.create_index('ix_notification_log_status', 'notification_log', ['status'])
    op.create_index('ix_notification_log_dedup_key', 'notification_log', ['dedup_key'])
    op.create_index('ix_notification_log_created_at', 'notification_log', ['created_at'])

    op.create_table(
        'notification_aggregates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('channel_id', sa.Integer(), nullable=False),
        sa.Column('dedup_key', sa.String(length=200), nullable=False),
        sa.Column('window_start', sa.DateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_event_id', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id']),
        sa.ForeignKeyConstraint(['last_event_id'], ['security_events.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_notification_aggregates_channel_id', 'notification_aggregates', ['channel_id'])
    op.create_index('ix_notification_aggregates_dedup_key', 'notification_aggregates', ['dedup_key'])


def downgrade():
    op.drop_index('ix_notification_aggregates_dedup_key', table_name='notification_aggregates')
    op.drop_index('ix_notification_aggregates_channel_id', table_name='notification_aggregates')
    op.drop_table('notification_aggregates')

    op.drop_index('ix_notification_log_created_at', table_name='notification_log')
    op.drop_index('ix_notification_log_dedup_key', table_name='notification_log')
    op.drop_index('ix_notification_log_status', table_name='notification_log')
    op.drop_index('ix_notification_log_event_id', table_name='notification_log')
    op.drop_index('ix_notification_log_channel_id', table_name='notification_log')
    op.drop_index('ix_notification_log_site_id', table_name='notification_log')
    op.drop_index('ix_notification_log_user_id', table_name='notification_log')
    op.drop_table('notification_log')

    op.drop_index('ix_notification_channels_created_at', table_name='notification_channels')
    op.drop_index('ix_notification_channels_channel_type', table_name='notification_channels')
    op.drop_index('ix_notification_channels_site_id', table_name='notification_channels')
    op.drop_index('ix_notification_channels_user_id', table_name='notification_channels')
    op.drop_table('notification_channels')
