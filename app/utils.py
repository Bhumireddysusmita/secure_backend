from fastapi import Request

from .config import get_settings


def mask_email(email: str | None) -> str:
    """john.doe@gmail.com -> j***.d***@gmail.com. Used in logs and reports; never log full addresses."""
    if not email or "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    parts = [p[:1] + "***" if p else "" for p in local.split(".")]
    return ".".join(parts) + "@" + domain


def client_ip(request: Request) -> str:
    """Client IP for rate limiting. X-Forwarded-For is trusted only when TRUST_PROXY=true."""
    if get_settings().trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:45]
    return (request.client.host if request.client else "unknown")[:45]
