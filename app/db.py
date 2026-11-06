import os
from collections.abc import Iterator

from sqlalchemy import create_engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from .config import get_settings


class Base(DeclarativeBase):
    pass


# Query params added by Supabase/Vercel for other clients (Prisma etc.). libpq rejects unknown
# params, so drop them before connecting.
_NON_LIBPQ_PARAMS = ("pgbouncer", "supa")


def _normalise_url(url: str) -> str:
    # Accept plain postgres:// URLs and use the psycopg 3 driver.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    parsed = make_url(url).difference_update_query(_NON_LIBPQ_PARAMS)
    return parsed.render_as_string(hide_password=False)


def _engine_options() -> dict:
    # Serverless (Vercel sets VERCEL=1): instances are short-lived and many can run at once,
    # so don't keep a pool per instance. Point DATABASE_URL at your provider's connection
    # pooler (Neon / Supabase / PgBouncer); prepared statements are disabled because
    # transaction-mode poolers don't support them.
    if os.environ.get("VERCEL") or os.environ.get("DB_NULL_POOL", "").lower() == "true":
        return {"poolclass": NullPool, "connect_args": {"prepare_threshold": None}}
    return {"pool_pre_ping": True}


engine = create_engine(_normalise_url(get_settings().database_url), future=True, **_engine_options())
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
