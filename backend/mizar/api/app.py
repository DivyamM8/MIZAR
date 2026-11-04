"""FastAPI application factory."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from sqlalchemy import Engine, text

from mizar.api.errors import install_error_handlers
from mizar.api.middleware import LocalGuardMiddleware
from mizar.api.routes import analysis, cases, correlation, events, files, jobs
from mizar.core.config import Settings
from mizar.db.engine import head_revision
from mizar.evidence.store import EvidenceStore
from mizar.versions import EVENT_SCHEMA_VERSION, MIZAR_VERSION, RULE_FORMAT_VERSION


def create_app(settings: Settings, engine: Engine, api_token: str) -> FastAPI:
    # Interactive docs are disabled: Swagger UI loads assets from a CDN (DESIGN.md §1.2).
    app = FastAPI(
        title="MIZAR",
        version=MIZAR_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.store = EvidenceStore(
        settings.evidence_dir, settings.staging_dir, settings.min_free_disk_bytes
    )

    install_error_handlers(app)
    app.add_middleware(
        LocalGuardMiddleware,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.allowed_origins,
        api_token=api_token,
    )

    app.include_router(cases.router)
    app.include_router(files.router)
    app.include_router(jobs.router)
    app.include_router(events.router)
    app.include_router(analysis.router)
    app.include_router(correlation.router)

    @app.get("/api/health")
    def health(request: Request) -> dict[str, Any]:
        db_engine: Engine = request.app.state.engine
        with db_engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
        expected = head_revision()
        return {
            "status": "ok" if revision == expected else "degraded",
            "db_revision": revision,
            "db_revision_expected": expected,
        }

    @app.get("/api/version")
    def version() -> dict[str, str]:
        return {
            "mizar_version": MIZAR_VERSION,
            "event_schema_version": EVENT_SCHEMA_VERSION,
            "rule_format_version": RULE_FORMAT_VERSION,
        }

    return app
