"""Vercel serverless entry point. Vercel's Python runtime serves the ASGI `app` found here."""

import sys
from pathlib import Path

# Make the project root importable so `app` resolves as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app as fastapi_app  # noqa: E402


async def app(scope, receive, send):
    # The app is served from the domain root (vercel.json routes every path here), so make sure
    # FastAPI never strips a prefix from incoming paths.
    if scope["type"] in ("http", "websocket"):
        scope = {**scope, "root_path": ""}
    await fastapi_app(scope, receive, send)
