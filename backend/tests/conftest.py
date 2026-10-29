from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from mizar.api.app import create_app
from mizar.core.config import Settings
from mizar.db.engine import make_engine, upgrade_db

TEST_TOKEN = "t" * 43
BASE_URL = "http://127.0.0.1:8730"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data")
    s.ensure_directories()
    return s


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    eng = make_engine(settings.db_path)
    upgrade_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def app(settings: Settings, engine: Engine) -> FastAPI:
    return create_app(settings, engine, TEST_TOKEN)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, base_url=BASE_URL)
