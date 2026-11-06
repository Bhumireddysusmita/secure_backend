"""Server-side input validation: the source of truth.

frontend/src/lib/validation.ts implements the same rules, in the same order, with the
same messages. test-data/validation-cases.json is run against both to prove they agree.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from email_validator import EmailNotValidError, validate_email

from .common_passwords import is_common_password

NAME_MIN, NAME_MAX = 2, 80
EMAIL_MAX = 254
PASSWORD_MIN, PASSWORD_MAX = 8, 72  # bcrypt only uses the first 72 bytes
CAPTCHA_TOKEN_MAX = 2048

MSG = {
    "invalid_value": "Invalid value",
    "name_required": "Full name is required",
    "name_min": f"Name must be at least {NAME_MIN} characters",
    "name_max": f"Name must be at most {NAME_MAX} characters",
    "name_chars": "Use letters, single spaces, hyphens and apostrophes only",
    "email_required": "Email is required",
    "email_max": f"Email must be at most {EMAIL_MAX} characters",
    "email_invalid": "Enter a valid email address",
    "password_required": "Password is required",
    "password_min": f"Password must be at least {PASSWORD_MIN} characters",
    "password_max": f"Password must be at most {PASSWORD_MAX} characters",
    "password_chars": "Password contains characters that aren't allowed",
    "password_letter": "Password must contain a letter",
    "password_number": "Password must contain a number",
    "password_common": "This password is too common. Choose a less predictable one",
    "password_personal": "Password must not contain your name or email",
    "confirm_required": "Please confirm your password",
    "confirm_mismatch": "Passwords do not match",
    "terms": "Please accept the Terms of Service and Privacy Policy",
    "login_password_max": "Password is too long",
}

# Typographic apostrophes (phone keyboards) are normalised to a plain one.
_APOSTROPHES = str.maketrans({"’": "'", "‘": "'", "ʼ": "'"})
_WHITESPACE_RUN = re.compile(r"\s+")
# Plain ASCII email (Gmail and most providers don't allow non-ASCII local parts).
_EMAIL_SHAPE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


class ValidationFailed(Exception):
    def __init__(self, fields: dict[str, str]):
        self.fields = fields


@dataclass(frozen=True)
class SignupInput:
    name: str
    email: str
    password: str
    captcha_token: str | None


@dataclass(frozen=True)
class LoginInput:
    email: str
    password: str
    captcha_token: str | None


class _WrongType:
    """Marker for a field that was sent as a number, list, object, etc."""


_WRONG = _WrongType()


def _get(body: dict[str, Any], key: str) -> str | None | _WrongType:
    value = body.get(key)
    if value is None or isinstance(value, str):
        return value
    return _WRONG


def _has_control_chars(s: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" for ch in s)


def normalise_name(raw: str) -> str:
    name = unicodedata.normalize("NFC", raw).translate(_APOSTROPHES)
    return _WHITESPACE_RUN.sub(" ", name).strip()


def _is_valid_name(name: str) -> bool:
    """Words of letters (plus combining marks, for scripts like Telugu or Hindi),
    joined by a single space, hyphen or apostrophe. Must start and end with a letter."""
    after_separator = True
    for ch in name:
        cat = unicodedata.category(ch)
        if cat.startswith("L"):
            after_separator = False
        elif cat.startswith("M"):
            if after_separator:
                return False
        elif ch in " '-":
            if after_separator:
                return False
            after_separator = True
        else:
            return False
    return not after_separator


def normalise_email(raw: str) -> str:
    return raw.strip().lower()


def check_name(raw: str | None | _WrongType) -> tuple[str | None, str | None]:
    if raw is _WRONG:
        return None, MSG["invalid_value"]
    if raw is None or not raw.strip():
        return None, MSG["name_required"]
    name = normalise_name(raw)
    if len(name) < NAME_MIN:
        return None, MSG["name_min"]
    if len(name) > NAME_MAX:
        return None, MSG["name_max"]
    if not _is_valid_name(name):
        return None, MSG["name_chars"]
    return name, None


def check_email(raw: str | None | _WrongType) -> tuple[str | None, str | None]:
    if raw is _WRONG:
        return None, MSG["invalid_value"]
    if raw is None or not raw.strip():
        return None, MSG["email_required"]
    email = normalise_email(raw)
    if len(email) > EMAIL_MAX:
        return None, MSG["email_max"]
    if not _EMAIL_SHAPE.match(email) or len(email.split("@")[0]) > 64:
        return None, MSG["email_invalid"]
    try:
        # Second opinion: RFC details plus special-use domains (localhost, .test, .invalid ...).
        validate_email(email, check_deliverability=False, allow_smtputf8=False)
    except EmailNotValidError:
        return None, MSG["email_invalid"]
    return email, None


def _personal_tokens(name: str | None, email: str | None) -> set[str]:
    tokens: set[str] = set()
    if name:
        tokens.update(re.split(r"[ '\-]", name.lower()))
    if email:
        tokens.update(re.split(r"[._+\-]", email.split("@")[0]))
    return {t for t in tokens if len(t) >= 4}


def check_new_password(
    raw: str | None | _WrongType, name: str | None = None, email: str | None = None
) -> tuple[str | None, str | None]:
    if raw is _WRONG:
        return None, MSG["invalid_value"]
    if raw is None or raw == "":
        return None, MSG["password_required"]
    if len(raw) < PASSWORD_MIN:
        return None, MSG["password_min"]
    if len(raw) > PASSWORD_MAX or len(raw.encode("utf-8")) > PASSWORD_MAX:
        return None, MSG["password_max"]
    if _has_control_chars(raw):
        # NUL in particular: bcrypt would silently ignore everything after it.
        return None, MSG["password_chars"]
    if not any(c.isalpha() for c in raw):
        return None, MSG["password_letter"]
    if not any(unicodedata.category(c) == "Nd" for c in raw):
        return None, MSG["password_number"]
    if is_common_password(raw):
        return None, MSG["password_common"]
    lowered = raw.lower()
    if any(t in lowered for t in _personal_tokens(name, email)):
        return None, MSG["password_personal"]
    return raw, None


def _captcha_token(body: dict[str, Any]) -> str | None:
    token = _get(body, "captchaToken")
    if not isinstance(token, str) or not token or len(token) > CAPTCHA_TOKEN_MAX:
        return None
    return token


def validate_signup(body: dict[str, Any]) -> SignupInput:
    fields: dict[str, str] = {}

    name, err = check_name(_get(body, "name"))
    if err:
        fields["name"] = err
    email, err = check_email(_get(body, "email"))
    if err:
        fields["email"] = err
    password, err = check_new_password(_get(body, "password"), name, email)
    if err:
        fields["password"] = err

    confirm = _get(body, "confirmPassword")
    if confirm is _WRONG:
        fields["confirmPassword"] = MSG["invalid_value"]
    elif not confirm:
        fields["confirmPassword"] = MSG["confirm_required"]
    elif confirm != _get(body, "password"):
        fields["confirmPassword"] = MSG["confirm_mismatch"]

    if body.get("acceptTerms") is not True:
        fields["acceptTerms"] = MSG["terms"]

    if fields:
        raise ValidationFailed(fields)
    assert name and email and password
    return SignupInput(name=name, email=email, password=password, captcha_token=_captcha_token(body))


def validate_login(body: dict[str, Any]) -> LoginInput:
    fields: dict[str, str] = {}

    email, err = check_email(_get(body, "email"))
    if err:
        fields["email"] = err

    password = _get(body, "password")
    if password is _WRONG:
        fields["password"] = MSG["invalid_value"]
    elif not password:
        fields["password"] = MSG["password_required"]
    elif len(password) > PASSWORD_MAX or len(password.encode("utf-8")) > PASSWORD_MAX:
        fields["password"] = MSG["login_password_max"]

    if fields:
        raise ValidationFailed(fields)
    assert email and isinstance(password, str)
    return LoginInput(email=email, password=password, captcha_token=_captcha_token(body))
