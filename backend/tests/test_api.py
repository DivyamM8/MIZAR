from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from mizar.api.middleware import TOKEN_HEADER
from mizar.core.errors import ErrorCode, MizarError

from .conftest import BASE_URL, TEST_TOKEN


def _assert_envelope(body: dict[str, object], code: str) -> None:
    error = body["error"]
    assert isinstance(error, dict)
    assert error["code"] == code
    assert isinstance(error["message"], str)
    assert str(error["request_id"]).startswith("req_")


def test_health_and_version(client: TestClient) -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    version = client.get("/api/version").json()
    assert version["event_schema_version"] == "1.0.0"


def test_security_headers(client: TestClient) -> None:
    response = client.get("/api/version")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"].startswith("req_")


def test_docs_are_disabled(client: TestClient) -> None:
    # Swagger UI would load assets from a CDN; these paths are not the API docs.
    for path in ("/docs", "/redoc"):
        assert "swagger" not in client.get(path).text.lower()
    assert client.get("/api/openapi.json").status_code == 200


def test_foreign_host_header_is_rejected(app: FastAPI) -> None:
    response = TestClient(app, base_url="http://evil.example:8730").get("/api/version")
    assert response.status_code == 400
    _assert_envelope(response.json(), "HOST_NOT_ALLOWED")


def test_cross_origin_request_is_rejected(client: TestClient) -> None:
    response = client.get("/api/version", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    _assert_envelope(response.json(), "ORIGIN_NOT_ALLOWED")
    same_origin = client.get("/api/version", headers={"Origin": BASE_URL})
    assert same_origin.status_code == 200


def _add_test_routes(app: FastAPI) -> None:
    class Body(BaseModel):
        name: str

    @app.post("/api/_test/echo")
    def echo(body: Body) -> dict[str, str]:
        return {"name": body.name}

    @app.get("/api/_test/mizar-error")
    def mizar_error() -> None:
        raise MizarError(ErrorCode.CASE_NOT_FOUND, "Case not found.", details={"case_id": "X"})

    @app.get("/api/_test/crash")
    def crash() -> None:
        raise RuntimeError("secret internal detail")


def test_unsafe_methods_require_token(app: FastAPI, client: TestClient) -> None:
    _add_test_routes(app)
    missing = client.post("/api/_test/echo", json={"name": "a"})
    assert missing.status_code == 401
    _assert_envelope(missing.json(), "AUTH_TOKEN_INVALID")
    wrong = client.post("/api/_test/echo", json={"name": "a"}, headers={TOKEN_HEADER: "x" * 43})
    assert wrong.status_code == 401
    ok = client.post("/api/_test/echo", json={"name": "a"}, headers={TOKEN_HEADER: TEST_TOKEN})
    assert ok.status_code == 200


def test_error_envelopes(app: FastAPI, client: TestClient) -> None:
    _add_test_routes(app)
    not_found = client.get("/api/nope")
    assert not_found.status_code == 404
    _assert_envelope(not_found.json(), "NOT_FOUND")

    invalid = client.post("/api/_test/echo", json={"wrong": 1}, headers={TOKEN_HEADER: TEST_TOKEN})
    assert invalid.status_code == 422
    _assert_envelope(invalid.json(), "VALIDATION_ERROR")
    assert "input" not in invalid.json()["error"]["details"]["errors"][0]

    domain = client.get("/api/_test/mizar-error")
    assert domain.status_code == 404
    _assert_envelope(domain.json(), "CASE_NOT_FOUND")
    assert domain.json()["error"]["details"] == {"case_id": "X"}


def test_unhandled_exception_hides_internals(app: FastAPI, client: TestClient) -> None:
    _add_test_routes(app)
    response = client.get("/api/_test/crash")
    assert response.status_code == 500
    _assert_envelope(response.json(), "INTERNAL_ERROR")
    assert "secret internal detail" not in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


def test_json_bodies_are_limited(app: FastAPI, client: TestClient) -> None:
    _add_test_routes(app)
    headers = {TOKEN_HEADER: TEST_TOKEN, "Content-Type": "application/json"}
    big = b'{"name": "' + b"a" * (1024 * 1024) + b'"}'
    too_large = client.post("/api/_test/echo", content=big, headers=headers)
    assert too_large.status_code == 413
    _assert_envelope(too_large.json(), "REQUEST_TOO_LARGE")

    def chunks():  # no Content-Length: sent chunked
        yield b'{"name": "a"}'

    chunked = client.post("/api/_test/echo", content=chunks(), headers=headers)
    assert chunked.status_code == 411
    _assert_envelope(chunked.json(), "LENGTH_REQUIRED")
    ok = client.post(
        "/api/_test/echo", json={"name": "a" * 1000}, headers={TOKEN_HEADER: TEST_TOKEN}
    )
    assert ok.status_code == 200


def test_uploads_are_not_limited_by_the_json_cap(client: TestClient) -> None:
    case = client.post(
        "/api/cases", json={"name": "c", "analyst_name": "a"}, headers={TOKEN_HEADER: TEST_TOKEN}
    ).json()
    body = b"Oct 27 08:00:00 srv01 sshd[1]: x\n" * 40_000  # ~1.3 MB
    response = client.post(
        f"/api/cases/{case['case_id']}/files",
        params={"filename": "auth.log"},
        content=body,
        headers={TOKEN_HEADER: TEST_TOKEN},
    )
    assert response.status_code == 201, response.text
