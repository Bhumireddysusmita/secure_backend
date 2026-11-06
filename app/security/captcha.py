"""Cloudflare Turnstile server-side verification. Fails closed: any error means "not verified"."""

import logging
from collections.abc import Callable

import httpx

from ..config import get_settings

log = logging.getLogger("auth.captcha")

CaptchaVerifier = Callable[[str | None, str], bool]


def verify_turnstile(
    token: str | None,
    ip: str,
    *,
    secret: str | None = None,
    client: httpx.Client | None = None,
) -> bool:
    if not token:
        log.info("captcha outcome=rejected reason=missing-token")
        return False

    settings = get_settings()
    data = {"secret": secret or settings.turnstile_secret_key, "response": token}
    if ip and ip != "unknown":
        data["remoteip"] = ip

    owns_client = client is None
    http = client or httpx.Client(timeout=settings.turnstile_timeout_seconds)
    try:
        res = http.post(settings.turnstile_verify_url, data=data)
        res.raise_for_status()
        body = res.json()
    except (httpx.HTTPError, ValueError) as exc:
        # Network error, timeout, non-2xx or invalid JSON: fail closed.
        log.warning("captcha outcome=error error=%s", type(exc).__name__)
        return False
    finally:
        if owns_client:
            http.close()

    success = body.get("success") is True
    codes = body.get("error-codes") or []
    log.info("captcha outcome=%s error_codes=%s", "passed" if success else "rejected", ",".join(map(str, codes)) or "-")
    return success


def get_captcha_verifier() -> CaptchaVerifier:
    """FastAPI dependency so tests can swap in a fake verifier."""
    return verify_turnstile
