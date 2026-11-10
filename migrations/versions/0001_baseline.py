"""baseline: existing schema (users, scans, alerts)

This revision represents the schema that was previously created at runtime by
`db.create_all()`. It performs no DDL. On an existing database run:
    alembic stamp 0001_baseline
before upgrading, so Alembic records the current schema as the starting point
without attempting to recreate it.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-10

"""

# revision identifiers, used by Alembic.
revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
