"""Vercel entrypoint: exposes the WHITE FastAPI application as ``app``.

Vercel's Python runtime looks for a FastAPI instance named ``app`` in ``app.py``. Locally, use
``white serve`` instead. On Vercel, WHITE runs in serverless mode automatically (VERCEL=1).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from white.api.app import create_app  # noqa: E402

app = create_app()
