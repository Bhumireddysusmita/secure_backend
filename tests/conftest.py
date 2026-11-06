"""Integration test setup.

Runs against a real PostgreSQL database named *_test (TEST_DATABASE_URL), migrated with
Alembic once per session and truncated before every test. CAPTCHA is mocked: the token
"pass" verifies, anything else fails.
"""

import os
from pathlib import Path

import pytest
from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parent.parent
_file_env = dotenv_values(BACKEND_DIR / ".env")

TEST_DB_URL = os.environ.get("TEST_DATABASE_URL") or _file_env.get("TEST_DATABASE_URL")
if not TEST_DB_URL:
    raise RuntimeError("Set TEST_DATABASE_URL (in backend/.env or the environment) to run the tests.")
if not TEST_DB_URL.rsplit("/", 1)[-1].split("?")[0].endswith("_test"):
    raise RuntimeError("Refusing to run: TEST_DATABASE_URL must point at a database whose name ends in _test.")

# Must be set before the app (and its settings/engine) is imported.
os.environ.update(
    {
        "APP_ENV": "test",
        "DATABASE_URL": TEST_DB_URL,
        "SESSION_SECRET": os.environ.get("SESSION_SECRET") or "test-only-session-secret-0123456789abcdef",
        "TURNSTILE_SECRET_KEY": "1x0000000000000000000000000000000AA",
        "BCRYPT_ROUNDS": "4",
        "APP_URL": "http://localhost:5173",
        "COOKIE_SECURE": "false",
        "LOGIN_MAX_FAILURES_PER_EMAIL": "5",
        "LOGIN_MAX_ATTEMPTS_PER_IP": "20",
        "SIGNUP_MAX_PER_IP": "10",
        "SIGNUP_MAX_PER_EMAIL": "5",
    }
)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security.captcha import get_captcha_verifier  # noqa: E402

PASS_TOKEN = "pass"


def fake_captcha(token: str | None, ip: str) -> bool:
    return token == PASS_TOKEN


@pytest.fixture(scope="session", autouse=True)
def migrated_db():
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_tables():
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE login_attempts, sessions, users RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def client():
    app.dependency_overrides[get_captcha_verifier] = lambda: fake_captcha
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def signup_body(**overrides):
    body = {
        "name": "Ada Testwell",
        "email": "ada.testwell@example.com",
        "password": "Sup3rSecret!",
        "confirmPassword": "Sup3rSecret!",
        "acceptTerms": True,
        "captchaToken": PASS_TOKEN,
    }
    body.update(overrides)
    return body


def login_body(**overrides):
    body = {"email": "ada.testwell@example.com", "password": "Sup3rSecret!", "captchaToken": PASS_TOKEN}
    body.update(overrides)
    return body
