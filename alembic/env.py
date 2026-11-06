import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from app import models  # noqa: F401  (registers tables on Base.metadata)
from app.db import Base, _normalise_url, engine

# Migrations need a session-mode connection (DDL + prepared statements), not the transaction
# pooler the app uses on Vercel. Supabase's integration provides POSTGRES_URL_NON_POOLING for this.
_migration_url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("POSTGRES_URL_NON_POOLING")
if _migration_url:
    engine = create_engine(_normalise_url(_migration_url), future=True)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=engine.url.render_as_string(hide_password=False),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
