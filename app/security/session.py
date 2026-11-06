import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from ..config import get_settings
from ..models import Session, User

COOKIE_NAME = "sid"


def hash_token(token: str) -> str:
    """HMAC-SHA256 of the cookie token, keyed with SESSION_SECRET. Only this is stored in the DB."""
    key = get_settings().session_secret.encode("utf-8")
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def create_session(db: DbSession, user_id) -> tuple[str, datetime]:
    """Creates a session row and returns (raw token for the cookie, expiry). Caller commits."""
    settings = get_settings()
    token = secrets.token_urlsafe(32)  # 32 random bytes
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.session_ttl_days)
    # Housekeeping: drop this user's expired sessions.
    db.execute(delete(Session).where(Session.user_id == user_id, Session.expires_at <= now))
    db.add(Session(user_id=user_id, token_hash=hash_token(token), expires_at=expires_at))
    return token, expires_at


def set_session_cookie(response: Response, token: str, expires_at: datetime) -> None:
    settings = get_settings()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.session_ttl_days * 24 * 3600,
        expires=expires_at,
        path="/",
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=COOKIE_NAME, path="/", httponly=True, secure=settings.secure_cookies, samesite="lax"
    )


def _token_from(request: Request) -> str | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token or len(token) > 128:
        return None
    return token


def get_current_user(db: DbSession, request: Request) -> User | None:
    token = _token_from(request)
    if not token:
        return None
    row = db.execute(
        select(User)
        .join(Session, Session.user_id == User.id)
        .where(Session.token_hash == hash_token(token), Session.expires_at > datetime.now(timezone.utc))
    ).scalar_one_or_none()
    return row


def destroy_session(db: DbSession, request: Request) -> None:
    token = _token_from(request)
    if token:
        db.execute(delete(Session).where(Session.token_hash == hash_token(token)))
