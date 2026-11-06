"""Enable row level security on all tables

Supabase exposes the public schema through its REST API to anyone holding the public anon key.
With RLS on and no policies, that API can't read or write these tables. The backend connects as
the table owner, which bypasses RLS, so the app itself is unaffected.

Revision ID: 0002_enable_rls
Revises: 0001_initial
Create Date: 2026-11-06
"""
from alembic import op

revision = "0002_enable_rls"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

TABLES = ("users", "sessions", "login_attempts")


def upgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
