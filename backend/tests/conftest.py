from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

import mizar.jobs.handlers  # noqa: F401  (registers job handlers)
from mizar.api.app import create_app
from mizar.api.middleware import TOKEN_HEADER
from mizar.core.config import Settings
from mizar.db.engine import make_engine, upgrade_db
from mizar.evidence.store import EvidenceStore
from mizar.jobs.worker import WorkerDeps, run_one

TEST_TOKEN = "t" * 43
BASE_URL = "http://127.0.0.1:8730"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path / "data", min_free_disk_bytes=0)
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


@pytest.fixture
def store(settings: Settings) -> EvidenceStore:
    return EvidenceStore(settings.evidence_dir, settings.staging_dir, min_free_bytes=0)


@pytest.fixture
def deps(settings: Settings, engine: Engine, store: EvidenceStore) -> WorkerDeps:
    return WorkerDeps(settings, engine, store)


@pytest.fixture
def run_jobs(deps: WorkerDeps) -> Callable[[], int]:
    """Run every queued job synchronously, as the worker would. Returns how many ran."""

    def run() -> int:
        count = 0
        stop = threading.Event()
        while run_one(deps, stop):
            count += 1
        return count

    return run


@pytest.fixture
def api(client: TestClient) -> TestClient:
    """Client that sends the API token, as the bundled UI does."""
    client.headers[TOKEN_HEADER] = TEST_TOKEN
    return client
