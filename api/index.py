"""Vercel serverless entry point. Vercel's Python runtime serves the ASGI `app` found here."""

import sys
from pathlib import Path

# Make the project root importable so `app` resolves as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

__all__ = ["app"]
