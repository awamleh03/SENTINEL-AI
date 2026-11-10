"""password resets: single-use, hashed, expiring tokens

Phase 3 (account recovery):
  * create `password_reset_tokens` — self-service password recovery. Only the
    SHA-256 hash of the token is stored; the raw token is delivered to the user
    once and never persisted, logged or returned by an API. Tokens are
    single-use (`used_at`) and bounded by `expires_at`. `requested_ip` records
    where the reset was requested, for auditing only.

No existing tables are altered.

Rollback: `alembic downgrade 0007_access_lists` drops only this table. Take a
backup before upgrading (copy `sentinel.db` for SQLite, `pg_dump` for
PostgreSQL). The table starts empty, so re-running the upgrade is safe.

Revision ID: 0008_password_resets
Revises: 0007_access_lists
Create Date: 2026-11-11

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0008_password_resets'
down_revision = '0007_access_lists'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('requested_ip', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])
    op.create_index('ix_password_reset_tokens_token_hash', 'password_reset_tokens',
                    ['token_hash'], unique=True)
    op.create_index('ix_password_reset_tokens_expires_at', 'password_reset_tokens', ['expires_at'])


def downgrade():
    op.drop_index('ix_password_reset_tokens_expires_at', table_name='password_reset_tokens')
    op.drop_index('ix_password_reset_tokens_token_hash', table_name='password_reset_tokens')
    op.drop_index('ix_password_reset_tokens_user_id', table_name='password_reset_tokens')
    op.drop_table('password_reset_tokens')
