import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import get_settings
from .db import SessionLocal
from .errors import ApiError, error_response
from .routes import auth

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("app")

settings = get_settings()

app = FastAPI(
    title="SecureAuth API",
    version="1.0.0",
    docs_url=None if settings.env == "production" else "/api/docs",
    redoc_url=None,
    openapi_url=None if settings.env == "production" else "/api/openapi.json",
)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_BODY_BYTES = 16 * 1024

# CSP for the HTML app: only our own scripts plus Cloudflare Turnstile.
HTML_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://challenges.cloudflare.com; "
    "frame-src https://challenges.cloudflare.com; "
    "connect-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"


def _request_origin(request: Request) -> str:
    host = request.headers.get("host", "")
    return f"{request.url.scheme}://{host}".rstrip("/")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    is_api = request.url.path.startswith("/api/")

    # Refuse oversized bodies before reading them. Auth payloads are well under 1 KB.
    if is_api and request.method in UNSAFE_METHODS:
        length = request.headers.get("content-length")
        if length is None and "chunked" in request.headers.get("transfer-encoding", "").lower():
            response = error_response(411, "length_required", "Content-Length is required.")
            _apply_headers(response, is_api=True)
            return response
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            response = error_response(413, "payload_too_large", "Request body is too large.")
            _apply_headers(response, is_api=True)
            return response

    # CSRF defence in depth (the cookie is also SameSite=Lax and auth bodies must be JSON):
    # reject cross-site browser requests to state-changing API routes. Skipped when APP_URL=*.
    if is_api and request.method in UNSAFE_METHODS and not settings.allow_all_origins:
        origin = request.headers.get("origin")
        if request.headers.get("sec-fetch-site") == "cross-site" or (
            origin
            and origin.rstrip("/") not in settings.allowed_origins
            and origin.rstrip("/") != _request_origin(request)
        ):
            log.warning("csrf outcome=rejected path=%s", request.url.path)
            response = error_response(403, "csrf_failed", "Cross-site request blocked.")
            _apply_headers(response, is_api=True)
            return response

    response = await call_next(request)
    _apply_headers(response, is_api=is_api)
    return response


# CORS, added after the security middleware so it runs first and answers preflight requests.
# Browsers reject "*" together with cookies, so "allow all" echoes back the caller's origin.
_cors_origins = {"allow_origin_regex": ".*"} if settings.allow_all_origins else {
    "allow_origins": sorted(settings.allowed_origins)
}
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
    **_cors_origins,
)


def _apply_headers(response, *, is_api: bool) -> None:
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    h.setdefault("Content-Security-Policy", API_CSP if is_api else HTML_CSP)
    if settings.env == "production":
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if is_api:
        # Auth responses must never be cached (also stops Back showing private data after logout).
        h["Cache-Control"] = "no-store"


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return error_response(exc.status, exc.code, exc.message, exc.fields, exc.headers)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_: Request, __: RequestValidationError) -> JSONResponse:
    # Malformed JSON, wrong content type or a non-object body.
    return error_response(400, "invalid_request", "Request body must be a JSON object.")


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
    return error_response(exc.status_code, code, str(exc.detail))


@app.exception_handler(Exception)
async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error type=%s", type(exc).__name__)
    return error_response(500, "server_error", "Something went wrong on our side. Please try again.")


app.include_router(auth.router)


@app.get("/api/health", tags=["health"])
def health() -> dict[str, object]:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"ok": True, "db": "up"}


# Optional single-origin deploy: serve the built React app with an SPA fallback.
if settings.frontend_dist:
    dist = Path(settings.frontend_dist).resolve()
    if (dist / "index.html").is_file():

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist in candidate.parents:
                return FileResponse(candidate)
            if full_path.startswith("api/"):
                return error_response(404, "not_found", "Not Found")
            return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})
