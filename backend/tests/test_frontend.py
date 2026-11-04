from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from mizar.api.app import create_app
from mizar.core.config import Settings

from .conftest import BASE_URL, TEST_TOKEN

INDEX = '<!doctype html><meta name="mizar-token" content="__MIZAR_TOKEN__"><div id="root"></div>'


@pytest.fixture
def ui(tmp_path: Path, settings: Settings, engine: Engine) -> TestClient:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(INDEX)
    (dist / "favicon.svg").write_text("<svg/>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path / "secret.txt").write_text("outside")
    app = create_app(settings.model_copy(update={"frontend_dir": dist}), engine, TEST_TOKEN)
    return TestClient(app, base_url=BASE_URL)


def test_index_carries_token_and_routes_fall_back(ui: TestClient) -> None:
    for path in ("/", "/cases/CASE-1/timeline", "/rules"):
        response = ui.get(path)
        assert response.status_code == 200
        assert f'content="{TEST_TOKEN}"' in response.text
        assert response.headers["cache-control"] == "no-store"
        assert "default-src 'self'" in response.headers["content-security-policy"]


def test_static_files(ui: TestClient) -> None:
    assert ui.get("/assets/app.js").text == "console.log(1)"
    assert ui.get("/favicon.svg").text == "<svg/>"


def test_api_paths_are_not_swallowed(ui: TestClient) -> None:
    response = ui.get("/api/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert ui.get("/api/version").json()["event_schema_version"] == "1.0.0"


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.txt",
        "/assets/../../secret.txt",
        "/%2e%2e/secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
    ],
)
def test_no_traversal(ui: TestClient, path: str) -> None:
    response = ui.get(path)
    assert "outside" not in response.text


def test_missing_build_explains_itself(tmp_path: Path, settings: Settings, engine: Engine) -> None:
    app = create_app(
        settings.model_copy(update={"frontend_dir": tmp_path / "none"}), engine, TEST_TOKEN
    )
    response = TestClient(app, base_url=BASE_URL).get("/")
    assert response.status_code == 503
    assert "npm run build" in response.text
