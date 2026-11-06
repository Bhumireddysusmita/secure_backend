"""Migrate and empty the E2E/pytest database (TEST_DATABASE_URL). Refuses any database not named *_test.

Usage: python scripts/reset_test_db.py
"""

import os
import sys
from pathlib import Path

from dotenv import dotenv_values

BACKEND = Path(__file__).resolve().parent.parent
url = os.environ.get("TEST_DATABASE_URL") or dotenv_values(BACKEND / ".env").get("TEST_DATABASE_URL")
if not url:
    sys.exit("TEST_DATABASE_URL is not set (backend/.env or environment).")
if not url.rsplit("/", 1)[-1].split("?")[0].endswith("_test"):
    sys.exit("Refusing: TEST_DATABASE_URL must point at a database whose name ends in _test.")

os.environ["DATABASE_URL"] = url  # before importing the app's engine
sys.path.insert(0, str(BACKEND))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db import engine  # noqa: E402

cfg = Config(str(BACKEND / "alembic.ini"))
cfg.set_main_option("script_location", str(BACKEND / "alembic"))
command.upgrade(cfg, "head")
with engine.begin() as conn:
    conn.execute(text("TRUNCATE login_attempts, sessions, users RESTART IDENTITY CASCADE"))
print("test database migrated and emptied")
