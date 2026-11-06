"""Auth endpoints. Order of checks for sign up and login:
per-IP rate limit -> input validation -> per-email limit/lockout -> CAPTCHA -> business logic.
"""

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from ..db import get_db
from ..errors import ApiError, rate_limited
from ..models import User
from ..security import rate_limit as rl
from ..security.captcha import CaptchaVerifier, get_captcha_verifier
from ..security.password import dummy_verify, hash_password, verify_password
from ..security.session import (
    clear_session_cookie,
    create_session,
    destroy_session,
    get_current_user,
    set_session_cookie,
)
from ..utils import client_ip, mask_email
from ..validation import ValidationFailed, validate_login, validate_signup

log = logging.getLogger("auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])

JsonBody = Annotated[dict[str, Any], Body()]
Db = Annotated[DbSession, Depends(get_db)]
Captcha = Annotated[CaptchaVerifier, Depends(get_captcha_verifier)]

INVALID_CREDENTIALS = "Incorrect email or password"


def user_json(user: User) -> dict[str, str]:
    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "createdAt": user.created_at.isoformat(),
    }


def _validation_error(exc: ValidationFailed) -> ApiError:
    return ApiError(400, "validation_error", "Please fix the highlighted fields.", fields=exc.fields)


def _captcha_failed() -> ApiError:
    return ApiError(403, "captcha_failed", "CAPTCHA check failed, please try again.")


@router.post("/signup", status_code=201)
def signup(body: JsonBody, request: Request, db: Db, verify_captcha: Captcha) -> JSONResponse:
    ip = client_ip(request)

    if retry := rl.signup_ip_retry_after(db, ip):
        log.info("signup outcome=rate_limited scope=ip")
        raise rate_limited(retry, "Too many sign-up attempts. Please try again later.")

    try:
        data = validate_signup(body)
    except ValidationFailed as exc:
        raise _validation_error(exc) from None

    if retry := rl.signup_email_retry_after(db, data.email):
        log.info("signup outcome=rate_limited scope=email email=%s", mask_email(data.email))
        raise rate_limited(retry, "Too many sign-up attempts. Please try again later.")

    # Every validated attempt counts toward the sign-up limits, including CAPTCHA failures.
    rl.record_attempt(db, kind="signup", ip=ip, email=data.email, success=False)

    if not verify_captcha(data.captcha_token, ip):
        raise _captcha_failed()

    if db.execute(select(User.id).where(User.email == data.email)).first():
        log.info("signup outcome=duplicate email=%s", mask_email(data.email))
        raise ApiError(409, "email_taken", "An account with this email already exists.", fields={"email": "An account with this email already exists"})

    user = User(name=data.name, email=data.email, password_hash=hash_password(data.password))
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        # Lost a race with a concurrent sign-up for the same email; the unique constraint wins.
        db.rollback()
        raise ApiError(409, "email_taken", "An account with this email already exists.", fields={"email": "An account with this email already exists"}) from None

    # If this browser was signed in to another account, end that session too.
    destroy_session(db, request)
    token, expires_at = create_session(db, user.id)
    db.commit()
    db.refresh(user)

    log.info("signup outcome=created email=%s", mask_email(user.email))
    response = JSONResponse({"ok": True, "user": user_json(user)}, status_code=201)
    set_session_cookie(response, token, expires_at)
    return response


@router.post("/login")
def login(body: JsonBody, request: Request, db: Db, verify_captcha: Captcha) -> JSONResponse:
    ip = client_ip(request)

    if retry := rl.login_ip_retry_after(db, ip):
        log.info("login outcome=rate_limited scope=ip")
        raise rate_limited(retry, "Too many login attempts. Please try again later.")

    try:
        data = validate_login(body)
    except ValidationFailed as exc:
        raise _validation_error(exc) from None

    if retry := rl.login_email_retry_after(db, data.email):
        log.info("login outcome=locked email=%s", mask_email(data.email))
        raise rate_limited(retry, "Too many failed attempts. This account is temporarily locked.")

    if not verify_captcha(data.captcha_token, ip):
        rl.record_attempt(db, kind="captcha", ip=ip, email=data.email, success=False)
        raise _captcha_failed()

    user = db.execute(select(User).where(User.email == data.email)).scalar_one_or_none()
    if user is None:
        dummy_verify(data.password)
        ok = False
    else:
        ok = verify_password(data.password, user.password_hash)

    if not ok or user is None:
        rl.record_attempt(db, kind="login", ip=ip, email=data.email, success=False)
        log.info("login outcome=invalid_credentials email=%s", mask_email(data.email))
        raise ApiError(401, "invalid_credentials", INVALID_CREDENTIALS)

    # Rotate: drop any session the browser already had, then issue a fresh one.
    destroy_session(db, request)
    token, expires_at = create_session(db, user.id)
    db.commit()
    rl.record_attempt(db, kind="login", ip=ip, email=data.email, success=True)

    log.info("login outcome=success email=%s", mask_email(user.email))
    response = JSONResponse({"ok": True, "user": user_json(user)})
    set_session_cookie(response, token, expires_at)
    return response


@router.post("/logout", status_code=204)
def logout(request: Request, db: Db) -> Response:
    destroy_session(db, request)
    db.commit()
    response = Response(status_code=204)
    clear_session_cookie(response)
    return response


@router.get("/me")
def me(request: Request, db: Db) -> JSONResponse:
    user = get_current_user(db, request)
    if user is None:
        raise ApiError(401, "unauthenticated", "You are not logged in.")
    return JSONResponse({"ok": True, "user": user_json(user)})
