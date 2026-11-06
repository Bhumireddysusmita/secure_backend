"""Rate limiting and lockout backed by the login_attempts table.

Login:   max N failed logins per email per window (lockout), max M attempts per IP per window.
Sign up: max N attempts per IP per window and max M per email per window.
Each check returns None when allowed, or the number of seconds until the caller may retry.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..config import get_settings
from ..models import LoginAttempt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _retry_after(db: DbSession, conditions: list, limit: int, window: timedelta) -> int | None:
    """If at least `limit` rows match within the window, return seconds until the limit-th newest ages out."""
    since = _now() - window
    stmt = (
        select(LoginAttempt.created_at)
        .where(*conditions, LoginAttempt.created_at > since)
        .order_by(LoginAttempt.created_at.desc())
        .offset(limit - 1)
        .limit(1)
    )
    nth_newest = db.execute(stmt).scalar_one_or_none()
    if nth_newest is None:
        return None
    return max(1, int((nth_newest + window - _now()).total_seconds()) + 1)


def record_attempt(db: DbSession, *, kind: str, ip: str, email: str | None, success: bool) -> None:
    db.add(LoginAttempt(kind=kind, ip=ip, email=email, success=success, created_at=_now()))
    db.commit()


def login_ip_retry_after(db: DbSession, ip: str) -> int | None:
    """Failed logins (bad credentials or CAPTCHA) per IP. Successful logins don't count, so many
    people sharing one network (office, home, mobile carrier) aren't blocked for logging in."""
    s = get_settings()
    return _retry_after(
        db,
        [LoginAttempt.ip == ip, LoginAttempt.kind.in_(("login", "captcha")), LoginAttempt.success.is_(False)],
        s.login_max_attempts_per_ip,
        timedelta(minutes=s.login_window_minutes),
    )


def login_email_retry_after(db: DbSession, email: str) -> int | None:
    """Lockout: counts failed logins for this email since the later of the window start and its last success."""
    s = get_settings()
    window = timedelta(minutes=s.login_window_minutes)
    last_success = db.execute(
        select(func.max(LoginAttempt.created_at)).where(
            LoginAttempt.email == email, LoginAttempt.kind == "login", LoginAttempt.success.is_(True)
        )
    ).scalar_one_or_none()
    conditions = [LoginAttempt.email == email, LoginAttempt.kind == "login", LoginAttempt.success.is_(False)]
    if last_success is not None:
        conditions.append(LoginAttempt.created_at > last_success)
    return _retry_after(db, conditions, s.login_max_failures_per_email, window)


def signup_ip_retry_after(db: DbSession, ip: str) -> int | None:
    s = get_settings()
    return _retry_after(
        db,
        [LoginAttempt.ip == ip, LoginAttempt.kind == "signup"],
        s.signup_max_per_ip,
        timedelta(minutes=s.signup_window_minutes),
    )


def signup_email_retry_after(db: DbSession, email: str) -> int | None:
    s = get_settings()
    return _retry_after(
        db,
        [LoginAttempt.email == email, LoginAttempt.kind == "signup"],
        s.signup_max_per_email,
        timedelta(minutes=s.signup_window_minutes),
    )
