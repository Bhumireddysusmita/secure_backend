"""Vercel serverless entry point. Vercel's Python runtime serves the ASGI `app` found here."""

import sys
from pathlib import Path

# Make the project root importable so `app` resolves as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app as fastapi_app  # noqa: E402


async def app(scope, receive, send):
    # Vercel sets root_path to "/api" (this file's folder). FastAPI would then strip "/api" from
    # every path and match "/health" instead of "/api/health", so every route 404s. The app is
    # served from the domain root via vercel.json rewrites, so the root path is always empty.
    if scope["type"] in ("http", "websocket"):
        scope = {**scope, "root_path": ""}
    await fastapi_app(scope, receive, send)
