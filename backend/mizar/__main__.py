"""Command line entry point: `mizar serve` and `mizar migrate`."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys

from pydantic import ValidationError

from mizar.core.config import Settings
from mizar.core.logging import configure_logging
from mizar.db.engine import make_engine, upgrade_db

log = logging.getLogger("mizar")


def _load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        print(f"Invalid MIZAR configuration:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _prepare(settings: Settings) -> None:
    # Everything MIZAR writes (database, evidence, exports) is private to this user.
    os.umask(0o077)
    configure_logging(settings.log_level)
    settings.ensure_directories()


def cmd_migrate(settings: Settings) -> int:
    _prepare(settings)
    upgrade_db(make_engine(settings.db_path))
    log.info("database is at the latest revision")
    return 0


def cmd_serve(settings: Settings) -> int:
    import uvicorn

    from mizar.api.app import create_app

    _prepare(settings)
    engine = make_engine(settings.db_path)
    upgrade_db(engine)
    # A fresh token per launch. MIZAR_API_TOKEN overrides it for development tooling.
    api_token = os.environ.get("MIZAR_API_TOKEN") or secrets.token_urlsafe(32)
    app = create_app(settings, engine, api_token)
    log.info("MIZAR listening on http://%s:%d", settings.host, settings.port)
    uvicorn.run(app, host=settings.host, port=settings.port, log_config=None)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mizar", description="MIZAR log analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the local web application")
    sub.add_parser("migrate", help="apply database migrations")
    args = parser.parse_args(argv)

    settings = _load_settings()
    if args.command == "serve":
        return cmd_serve(settings)
    return cmd_migrate(settings)


if __name__ == "__main__":
    raise SystemExit(main())
