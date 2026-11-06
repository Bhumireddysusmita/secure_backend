from functools import lru_cache

import bcrypt

from ..config import get_settings


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=get_settings().bcrypt_rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


@lru_cache
def _dummy_hash() -> str:
    return hash_password("dummy-password-for-timing-1")


def dummy_verify(password: str) -> None:
    """Run a bcrypt compare even when the email is unknown, so timing doesn't reveal which emails exist."""
    verify_password(password, _dummy_hash())
