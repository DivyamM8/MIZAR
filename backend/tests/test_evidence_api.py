import gzip
import hashlib
import io
import os
import tarfile
import threading
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, update

from mizar.core.config import Settings
from mizar.db.tables import jobs
from mizar.evidence.store import EvidenceStore
from mizar.jobs.worker import WorkerDeps, run_one

SYSLOG = (
    b"Oct 29 12:00:01 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    b"Oct 29 12:00:02 web01 sshd[1234]: Accepted password for root from 203.0.113.5 port 22\n"
)
RunJobs = Callable[[], int]


def _case(api: TestClient, name: str = "Incident 42", **extra: Any) -> dict[str, Any]:
    response = api.post("/api/cases", json={"name": name, "analyst_name": "R. Analyst", **extra})
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def _upload(
    api: TestClient, case_id: str, data: bytes, filename: str, **params: Any
) -> dict[str, Any]:
    response = api.post(
        f"/api/cases/{case_id}/files", params={"filename": filename, **params}, content=data
    )
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


def _files(api: TestClient, case_id: str) -> list[dict[str, Any]]:
    return api.get(f"/api/cases/{case_id}/files").json()  # type: ignore[no-any-return]


def _codes(file_row: dict[str, Any]) -> list[str]:
    return [m["code"] for m in file_row["validation_messages"]]


def _error_code(response: Any) -> str:
    return response.json()["error"]["code"]  # type: ignore[no-any-return]


# --- cases ---------------------------------------------------------------------------


def test_case_crud(api: TestClient) -> None:
    case = _case(api, reference="INC-42", default_timezone_hint="Asia/Kolkata")
    assert case["case_id"].startswith("CASE-") and case["file_count"] == 0
    assert api.get(f"/api/cases/{case['case_id']}").json()["reference"] == "INC-42"
    assert [c["case_id"] for c in api.get("/api/cases").json()] == [case["case_id"]]

    patched = api.patch(f"/api/cases/{case['case_id']}", json={"description": "SSH incident"})
    assert patched.json()["description"] == "SSH incident"
    assert patched.json()["name"] == "Incident 42"

    assert api.get("/api/cases/CASE-nope").status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {"name": "x"},
        {"name": "", "analyst_name": "a"},
        {"name": "x", "analyst_name": "a", "default_timezone_hint": "Mars/Olympus"},
        {"name": "x", "analyst_name": "a", "unexpected": 1},
    ],
)
def test_case_validation(api: TestClient, body: dict[str, Any]) -> None:
    response = api.post("/api/cases", json=body)
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


def test_case_required_fields_cannot_be_nulled(api: TestClient) -> None:
    case = _case(api)
    response = api.patch(f"/api/cases/{case['case_id']}", json={"name": None})
    assert response.status_code == 422


# --- upload and ingest ---------------------------------------------------------------


def test_upload_hashes_and_detects(api: TestClient, run_jobs: RunJobs) -> None:
    case = _case(api, default_timezone_hint="UTC")
    uploaded = _upload(api, case["case_id"], SYSLOG, "auth.log", year_hint=2026)
    source = uploaded["source_file"]
    assert source["sha256"] == hashlib.sha256(SYSLOG).hexdigest()
    assert source["size_bytes"] == len(SYSLOG)
    assert source["status"] == "stored"
    assert source["integrity_status"] == "verified"
    assert source["timezone_hint"] == "UTC"  # inherited from the case
    assert source["year_hint"] == 2026
    assert source["uploaded_by"] == "R. Analyst"

    assert run_jobs() == 1
    job = api.get(f"/api/jobs/{uploaded['job_id']}").json()
    assert job["status"] == "succeeded"
    (row,) = _files(api, case["case_id"])
    assert row["status"] == "ready"
    assert row["detected_format"] == row["effective_format"] == "linux_syslog"
    assert row["detection_candidates"][0]["format_id"] == "linux_syslog"


def test_format_override_is_recorded_alongside_detection(
    api: TestClient, run_jobs: RunJobs
) -> None:
    case = _case(api)
    _upload(api, case["case_id"], SYSLOG, "auth.log", format_override="generic_text")
    run_jobs()
    (row,) = _files(api, case["case_id"])
    assert row["detected_format"] == "linux_syslog"
    assert row["effective_format"] == "generic_text"


@pytest.mark.parametrize(
    "params",
    [
        {"filename": "a.log", "timezone_hint": "Not/AZone"},
        {"filename": "a.log", "format_override": "nope"},
        {"filename": "a.log", "year_hint": 1800},
        {"filename": "a\x00.log"},
        {},
    ],
)
def test_upload_validation(api: TestClient, params: dict[str, Any]) -> None:
    case = _case(api)
    response = api.post(f"/api/cases/{case['case_id']}/files", params=params, content=b"x")
    assert response.status_code == 422
    assert _error_code(response) == "VALIDATION_ERROR"


def test_upload_requires_token_and_case(
    client: TestClient, api: TestClient, store: EvidenceStore
) -> None:
    case = _case(api)
    del api.headers["x-mizar-token"]
    response = client.post(f"/api/cases/{case['case_id']}/files?filename=a", content=b"x")
    assert response.status_code == 401
    response = client.post(
        "/api/cases/CASE-missing/files?filename=a",
        content=b"x",
        headers={"x-mizar-token": "t" * 43},
    )
    assert response.status_code == 404
    assert not store.exists(hashlib.sha256(b"x").hexdigest())
    assert list(store.staging_dir.iterdir()) == []


def _limit_settings(app: FastAPI, **limits: int) -> None:
    current: Settings = app.state.settings
    app.state.settings = current.model_copy(update=limits)


def test_upload_size_limits(app: FastAPI, api: TestClient, store: EvidenceStore) -> None:
    case = _case(api)
    _limit_settings(app, max_file_bytes=10)
    response = api.post(f"/api/cases/{case['case_id']}/files?filename=a", content=b"x" * 11)
    assert response.status_code == 413
    assert _error_code(response) == "FILE_TOO_LARGE"
    assert list(store.staging_dir.iterdir()) == []

    _limit_settings(app, max_file_bytes=1000, max_case_uncompressed_bytes=15)
    _upload(api, case["case_id"], b"y" * 10, "first.log")
    response = api.post(f"/api/cases/{case['case_id']}/files?filename=b", content=b"z" * 10)
    assert response.status_code == 413
    assert _error_code(response) == "CASE_BUDGET_EXCEEDED"


def test_duplicate_and_empty_uploads_are_flagged(api: TestClient) -> None:
    case = _case(api)
    first = _upload(api, case["case_id"], SYSLOG, "auth.log")
    second = _upload(api, case["case_id"], SYSLOG, "auth.log.copy")
    assert second["source_file"]["source_file_id"] != first["source_file"]["source_file_id"]
    assert second["source_file"]["sequence"] == 2
    assert _codes(second["source_file"]) == ["DUPLICATE_UPLOAD"]
    empty = _upload(api, case["case_id"], b"", "empty.log")
    assert _codes(empty["source_file"]) == ["EMPTY_FILE"]


def _targz(members: dict[str, bytes]) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return gzip.compress(tar_buffer.getvalue(), mtime=0)


def test_nested_archive_is_expanded_into_a_tree(api: TestClient, run_jobs: RunJobs) -> None:
    case = _case(api)
    bundle = _targz(
        {
            "var/log/auth.log": SYSLOG,
            "var/log/auth.log.2.gz": gzip.compress(SYSLOG + b"older\n", mtime=0),
            "../../escape.log": b"x",
        }
    )
    _upload(api, case["case_id"], bundle, "collection.tar.gz", timezone_hint="Europe/Berlin")
    assert run_jobs() == 1
    rows = {
        r["archive_member_path"] or r["original_filename"]: r for r in _files(api, case["case_id"])
    }

    root = rows["collection.tar.gz"]
    assert (root["status"], root["container_type"], root["archive_depth"]) == (
        "expanded",
        "gzip",
        0,
    )
    tar = rows["collection.tar"]
    assert (tar["status"], tar["container_type"], tar["parent_file_id"]) == (
        "expanded",
        "tar",
        root["source_file_id"],
    )
    assert "ARCHIVE_PATH_TRAVERSAL" in _codes(tar)
    auth = rows["var/log/auth.log"]
    assert (auth["status"], auth["detected_format"], auth["archive_depth"]) == (
        "ready",
        "linux_syslog",
        2,
    )
    assert auth["timezone_hint"] == "Europe/Berlin"  # inherited down the tree
    older = rows["auth.log.2"]
    assert older["archive_depth"] == 3 and older["status"] == "ready"
    assert len(rows) == 5


def test_archive_depth_limit(api: TestClient, deps: WorkerDeps) -> None:
    case = _case(api)
    _upload(api, case["case_id"], _targz({"a.log": SYSLOG}), "c.tar.gz")
    shallow = WorkerDeps(
        deps.settings.model_copy(update={"max_archive_depth": 1}), deps.engine, deps.store
    )
    while run_one(shallow, threading.Event()):
        pass
    rows = {r["original_filename"]: r for r in _files(api, case["case_id"])}
    assert rows["c.tar.gz"]["status"] == "expanded"
    inner = rows["c.tar"]
    assert inner["status"] == "unsupported"
    assert inner["container_type"] == "tar"
    assert "ARCHIVE_DEPTH_LIMIT" in _codes(inner)
    assert len(rows) == 2


def test_ingest_retry_does_not_duplicate_members(
    api: TestClient, run_jobs: RunJobs, engine: Engine
) -> None:
    case = _case(api)
    uploaded = _upload(api, case["case_id"], _targz({"a.log": SYSLOG, "b.log": SYSLOG}), "c.tgz")
    run_jobs()
    count = len(_files(api, case["case_id"]))
    # Re-run the same job, as the worker does after a crash.
    with engine.begin() as conn:
        conn.execute(
            update(jobs).where(jobs.c.job_id == uploaded["job_id"]).values(status="queued")
        )
    run_jobs()
    assert len(_files(api, case["case_id"])) == count


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"\x00\x01\x02\x03\xfe\xff" * 50, "UNSUPPORTED_BINARY"),
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 50, "UNSUPPORTED_ARCHIVE"),
    ],
)
def test_unsupported_content_is_kept_as_evidence(
    api: TestClient, run_jobs: RunJobs, data: bytes, code: str
) -> None:
    case = _case(api)
    _upload(api, case["case_id"], data, "blob.bin")
    run_jobs()
    (row,) = _files(api, case["case_id"])
    assert row["status"] == "unsupported"
    assert code in _codes(row)


def test_corrupt_archive_marks_file_failed(api: TestClient, run_jobs: RunJobs) -> None:
    case = _case(api)
    uploaded = _upload(api, case["case_id"], b"PK\x03\x04" + b"\xff" * 64, "broken.zip")
    run_jobs()
    (row,) = _files(api, case["case_id"])
    assert row["status"] == "failed"
    assert "ARCHIVE_CORRUPT" in _codes(row)
    assert api.get(f"/api/jobs/{uploaded['job_id']}").json()["status"] == "succeeded"


# --- verification --------------------------------------------------------------------


def test_verification_detects_tampering(
    api: TestClient, run_jobs: RunJobs, store: EvidenceStore
) -> None:
    case = _case(api)
    good = _upload(api, case["case_id"], SYSLOG, "good.log")["source_file"]
    bad = _upload(api, case["case_id"], b"other content\n", "bad.log")["source_file"]
    run_jobs()
    path = store.blob_path(bad["sha256"])
    os.chmod(path, 0o644)
    path.write_bytes(b"altered content\n")

    job_id = api.post(f"/api/cases/{case['case_id']}/verify").json()["job_id"]
    run_jobs()
    result = api.get(f"/api/jobs/{job_id}").json()["result"]
    assert result["counts"] == {"verified": 1, "integrity_failed": 1, "missing": 0}
    rows = {r["source_file_id"]: r for r in _files(api, case["case_id"])}
    assert rows[good["source_file_id"]]["integrity_status"] == "verified"
    assert rows[bad["source_file_id"]]["integrity_status"] == "integrity_failed"


# --- jobs ----------------------------------------------------------------------------


def test_job_endpoints(api: TestClient) -> None:
    case = _case(api)
    job_id = _upload(api, case["case_id"], SYSLOG, "a.log")["job_id"]
    listed = api.get(f"/api/cases/{case['case_id']}/jobs").json()
    assert [j["job_id"] for j in listed] == [job_id]
    cancelled = api.post(f"/api/jobs/{job_id}/cancel").json()
    assert cancelled["status"] == "cancelled"
    again = api.post(f"/api/jobs/{job_id}/cancel")
    assert again.status_code == 409 and _error_code(again) == "JOB_NOT_CANCELLABLE"
    assert api.get("/api/jobs/JOB-missing").status_code == 404


# --- deletion ------------------------------------------------------------------------


def _delete(api: TestClient, case_id: str, confirm: str) -> Any:
    return api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": confirm})


def test_delete_requires_exact_name(api: TestClient) -> None:
    case = _case(api, name="Incident 42")
    response = _delete(api, case["case_id"], "incident 42")
    assert response.status_code == 422 and _error_code(response) == "CASE_NAME_MISMATCH"
    assert api.get(f"/api/cases/{case['case_id']}").status_code == 200


def test_delete_removes_everything_but_shared_blobs(
    api: TestClient, run_jobs: RunJobs, store: EvidenceStore, settings: Settings
) -> None:
    doomed = _case(api, name="Doomed")
    keeper = _case(api, name="Keeper")
    shared = _upload(api, doomed["case_id"], SYSLOG, "shared.log")["source_file"]["sha256"]
    _upload(api, keeper["case_id"], SYSLOG, "shared-copy.log")
    own = _upload(api, doomed["case_id"], _targz({"x.log": b"only here\n"}), "own.tgz")
    run_jobs()
    own_hashes = [r["sha256"] for r in _files(api, doomed["case_id"]) if r["sha256"] != shared]
    assert len(own_hashes) == 3 and own["source_file"]["sha256"] in own_hashes
    exports = settings.exports_dir / doomed["case_id"]
    exports.mkdir()
    (exports / "report.pdf").write_bytes(b"%PDF")

    response = _delete(api, doomed["case_id"], "Doomed")
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["source_files_deleted"], body["blobs_deleted"], body["blobs_retained_shared"]) == (
        4,
        3,
        1,
    )
    assert api.get(f"/api/cases/{doomed['case_id']}").status_code == 404
    assert store.exists(shared)
    assert not any(store.exists(h) for h in own_hashes)
    assert not exports.exists()
    assert len(_files(api, keeper["case_id"])) == 1


def test_delete_refused_while_job_running(api: TestClient, engine: Engine) -> None:
    case = _case(api, name="Busy")
    job_id = _upload(api, case["case_id"], SYSLOG, "a.log")["job_id"]
    with engine.begin() as conn:
        conn.execute(update(jobs).where(jobs.c.job_id == job_id).values(status="running"))
    response = _delete(api, case["case_id"], "Busy")
    assert response.status_code == 409 and _error_code(response) == "CASE_BUSY"
