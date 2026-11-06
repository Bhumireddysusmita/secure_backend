from fastapi.responses import JSONResponse


class ApiError(Exception):
    """Raised anywhere in a request to return { ok: false, error: { code, message, fields? } }."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        fields: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.status = status
        self.code = code
        self.message = message
        self.fields = fields
        self.headers = headers


def error_response(
    status: int, code: str, message: str, fields: dict[str, str] | None = None, headers: dict[str, str] | None = None
) -> JSONResponse:
    error: dict[str, object] = {"code": code, "message": message}
    if fields:
        error["fields"] = fields
    return JSONResponse({"ok": False, "error": error}, status_code=status, headers=headers)


def rate_limited(retry_after_seconds: int, message: str) -> ApiError:
    return ApiError(429, "rate_limited", message, headers={"Retry-After": str(max(1, retry_after_seconds))})
