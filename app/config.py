from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """All configuration comes from environment variables (or backend/.env, which is git-ignored)."""

    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["development", "test", "production"] = Field(default="development", alias="APP_ENV")

    database_url: str = Field(alias="DATABASE_URL")
    session_secret: str = Field(min_length=32, alias="SESSION_SECRET")

    turnstile_secret_key: str = Field(alias="TURNSTILE_SECRET_KEY")
    turnstile_verify_url: str = Field(
        default="https://challenges.cloudflare.com/turnstile/v0/siteverify", alias="TURNSTILE_VERIFY_URL"
    )
    turnstile_timeout_seconds: float = Field(default=5.0, alias="TURNSTILE_TIMEOUT_SECONDS")

    # Comma-separated list of browser origins allowed to POST (CSRF same-origin check).
    app_url: str = Field(default="http://localhost:5173", alias="APP_URL")

    # Cookie Secure flag. Defaults to on in production.
    cookie_secure: bool | None = Field(default=None, alias="COOKIE_SECURE")
    session_ttl_days: int = Field(default=7, alias="SESSION_TTL_DAYS")

    bcrypt_rounds: int = Field(default=12, ge=4, le=15, alias="BCRYPT_ROUNDS")

    # Only trust X-Forwarded-For when running behind a known reverse proxy.
    trust_proxy: bool = Field(default=False, alias="TRUST_PROXY")

    # Rate limits (see docs/security.md). Overridable so the 25-user E2E run
    # from one IP can raise the per-IP caps without touching code.
    login_max_failures_per_email: int = Field(default=5, alias="LOGIN_MAX_FAILURES_PER_EMAIL")
    login_max_attempts_per_ip: int = Field(default=20, alias="LOGIN_MAX_ATTEMPTS_PER_IP")
    login_window_minutes: int = Field(default=15, alias="LOGIN_WINDOW_MINUTES")
    signup_max_per_ip: int = Field(default=10, alias="SIGNUP_MAX_PER_IP")
    signup_max_per_email: int = Field(default=5, alias="SIGNUP_MAX_PER_EMAIL")
    signup_window_minutes: int = Field(default=60, alias="SIGNUP_WINDOW_MINUTES")

    # Optional: serve the built React app (frontend/dist) from the API server.
    frontend_dist: Path | None = Field(default=None, alias="FRONTEND_DIST")

    @property
    def allowed_origins(self) -> set[str]:
        return {o.strip().rstrip("/") for o in self.app_url.split(",") if o.strip()}

    @property
    def secure_cookies(self) -> bool:
        return self.cookie_secure if self.cookie_secure is not None else self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
