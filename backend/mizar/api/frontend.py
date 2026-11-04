"""Serves the built web UI (DESIGN.md §17).

index.html carries the per-launch API token in a <meta> tag, so the page can
send it with state-changing requests without any inline script (the CSP
forbids those). Other origins cannot read the page, and the Host check blocks
DNS rebinding. Only files directly in the build directory and its assets/
folder are served.
"""

from __future__ import annotations

import html
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

_PLACEHOLDER = 'content="__MIZAR_TOKEN__"'
_NOT_BUILT = (
    "The MIZAR API is running, but the web UI has not been built.\n"
    "Build it with: cd frontend && npm ci && npm run build\n"
)


def mount_frontend(app: FastAPI, root: Path, api_token: str) -> None:
    """Static assets and top-level files get routes; other paths fall back via ui_page()."""
    app.state.ui_page = None
    index_file = root / "index.html"
    if not index_file.is_file():
        app.state.ui_page = PlainTextResponse(_NOT_BUILT, status_code=503)
        return
    template = index_file.read_text(encoding="utf-8")
    if _PLACEHOLDER not in template:
        raise RuntimeError("frontend index.html lacks the mizar-token placeholder")
    page = template.replace(_PLACEHOLDER, f'content="{html.escape(api_token, quote=True)}"')
    app.state.ui_page = page
    if (root / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")
    for entry in root.iterdir():
        if entry.is_file() and entry.name != "index.html":
            _serve_file(app, entry)


def _serve_file(app: FastAPI, entry: Path) -> None:
    @app.get(f"/{entry.name}", include_in_schema=False, response_model=None)
    def top_level_file() -> FileResponse:
        return FileResponse(entry)


def ui_page(request: Request) -> Response | None:
    """The app shell for a GET that matched no route outside /api (client-side routes)."""
    if request.method != "GET":
        return None
    path = request.url.path
    if path == "/api" or path.startswith("/api/"):
        return None
    page = getattr(request.app.state, "ui_page", None)
    if page is None:
        return None
    if isinstance(page, Response):
        return page
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})
