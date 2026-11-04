import gzip
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select

from mizar.db.tables import event_groups, events, raw_records
from mizar.evidence.store import EvidenceStore

from .test_parsers import EVTX_SAMPLES

RunJobs = Callable[[], int]
AUTH = (
    b"Oct 29 12:00:01 web01 sshd[10]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    b"Oct 29 12:00:01 web01 sshd[10]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    b"Oct 29 12:00:09 web01 sshd[10]: Accepted password for root from 203.0.113.5 port 22 ssh2\n"
    b"Oct 29 12:01:00 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/id\n"
)


def _case(api: TestClient) -> str:
    response = api.post("/api/cases", json={"name": "Parse", "analyst_name": "R. Analyst"})
    return str(response.json()["case_id"])


def _upload(api: TestClient, case_id: str, data: bytes, filename: str, **params: Any) -> Any:
    response = api.post(
        f"/api/cases/{case_id}/files", params={"filename": filename, **params}, content=data
    )
    assert response.status_code == 201, response.text
    return response.json()


def _files(api: TestClient, case_id: str) -> dict[str, Any]:
    return {f["original_filename"]: f for f in api.get(f"/api/cases/{case_id}/files").json()}


def _events(api: TestClient, case_id: str, **params: Any) -> Any:
    response = api.get(f"/api/cases/{case_id}/events", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_upload_parses_into_events(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case(api)
    _upload(api, case_id, AUTH, "auth.log", year_hint=2026, timezone_hint="Europe/Berlin")
    run_jobs()
    parse = _files(api, case_id)["auth.log"]["parse"]
    assert parse["status"] == "succeeded"
    assert (parse["records_total"], parse["records_parsed"]) == (4, 4)
    assert (parse["parser_name"], parse["timezone_hint"], parse["year_hint"]) == (
        "linux.syslog",
        "Europe/Berlin",
        2026,
    )
    assert parse["first_timestamp_utc"].startswith("2026-10-29T11:00:01")

    page = _events(api, case_id)
    assert page["total"] == 4
    assert [e["event_type"] for e in page["items"]] == [
        "logon_failed",
        "logon_failed",
        "logon",
        "sudo_command",
    ]
    assert _events(api, case_id, event_type="logon_failed")["total"] == 2
    assert _events(api, case_id, ip="203.0.113.5")["total"] == 3
    assert _events(api, case_id, q="COMMAND=/bin/id")["total"] == 1
    assert _events(api, case_id, start="2026-10-29T11:00:05Z")["total"] == 2

    detail = api.get(f"/api/events/{page['items'][2]['event_id']}").json()
    assert detail["raw_record"]["text"] == AUTH.splitlines()[2].decode()
    assert detail["raw_record"]["lossless"] is True
    assert detail["raw_record"]["source"] == "evidence_file"
    assert detail["raw_record"]["verified"] is True
    assert detail["ingestion_time"] == parse["started_at"]
    assert detail["parser_version"] == "1.0.0" and detail["schema_version"] == "1.0.0"
    assert detail["original_record_reference"]["line"] == 3
    assert [g["group_type"] for g in detail["groups"]] == ["session"]  # sshd[10]


def test_naive_time_filter_is_rejected(api: TestClient) -> None:
    case_id = _case(api)
    response = api.get(f"/api/cases/{case_id}/events", params={"start": "2026-10-29T11:00:00"})
    assert response.status_code == 422
    assert response.json()["error"]["details"]["errors"][0]["loc"] == ["query", "start"]


def test_reparse_with_new_hint_keeps_event_ids(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case(api)
    source = _upload(api, case_id, AUTH, "auth.log", year_hint=2026)["source_file"]
    run_jobs()
    before = _events(api, case_id)["items"]
    assert all(e["timestamp_utc"] is None for e in before)  # no timezone yet

    response = api.post(
        f"/api/cases/{case_id}/files/{source['source_file_id']}/reparse",
        json={"timezone_hint": "UTC"},
    )
    assert response.status_code == 202
    run_jobs()
    after = _events(api, case_id)["items"]
    assert [e["event_id"] for e in after] == [e["event_id"] for e in before]
    assert after[0]["timestamp_utc"].startswith("2026-10-29T12:00:01")
    assert after[0]["timezone_assumption"] == "analyst_hint:UTC"
    assert _files(api, case_id)["auth.log"]["parse"]["timezone_hint"] == "UTC"


def test_reparse_validation(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case(api)
    log = _upload(api, case_id, AUTH, "auth.log")["source_file"]
    archive = _upload(api, case_id, gzip.compress(AUTH), "auth.log.gz")["source_file"]
    run_jobs()
    url = f"/api/cases/{case_id}/files/{{}}/reparse"
    assert (
        api.post(url.format(log["source_file_id"]), json={"format_override": "x"}).status_code
        == 422
    )
    assert (
        api.post(url.format(log["source_file_id"]), json={"timezone_hint": "Mars/X"}).status_code
        == 422
    )
    refused = api.post(url.format(archive["source_file_id"]), json={})
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "FILE_NOT_PARSEABLE"


def test_same_log_collected_twice_forms_duplicate_groups(
    api: TestClient, run_jobs: RunJobs, engine: Engine
) -> None:
    case_id = _case(api)
    _upload(api, case_id, AUTH, "auth.log")
    _upload(api, case_id, AUTH[: AUTH.index(b"Oct 29 12:01")], "auth.log.copy")
    run_jobs()
    with engine.connect() as conn:
        groups = conn.execute(
            select(event_groups.c.group_key, event_groups.c.member_count).where(
                event_groups.c.group_type == "duplicate"
            )
        ).all()
    # Lines 1 and 2 are identical within each file: still two separate groups, never merged.
    assert sorted(count for _, count in groups) == [2, 2, 2]
    first = _events(api, case_id, event_type="logon_failed")["items"][0]
    detail = api.get(f"/api/events/{first['event_id']}").json()
    (group,) = [g for g in detail["groups"] if g["group_type"] == "duplicate"]
    assert len({m["source_file_id"] for m in group["members"]}) == 2
    assert _events(api, case_id)["total"] == 7  # nothing was removed


def test_evtx_upload_with_damaged_chunks(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case(api)
    data = (EVTX_SAMPLES / "sample_with_a_bad_chunk_magic.evtx").read_bytes()
    _upload(api, case_id, data, "Application.evtx")
    run_jobs()
    parse = _files(api, case_id)["Application.evtx"]["parse"]
    assert parse["status"] == "succeeded_with_warnings"
    assert parse["records_total"] == 270
    assert parse["file_problems"]["counts"] == {"EVTX_CHUNK_UNREADABLE": 2}


def test_file_level_failure_keeps_events(
    api: TestClient, run_jobs: RunJobs, tmp_path: Path
) -> None:
    case_id = _case(api)
    broken = b'[{"Event": {"System": {"EventID": 1}}}, {"Event": '
    _upload(api, case_id, broken, "export.json", format_override="windows_evtx_json")
    run_jobs()
    parse = _files(api, case_id)["export.json"]["parse"]
    assert parse["status"] == "failed"
    assert parse["error_code"] == "JSON_INVALID"
    assert parse["records_total"] == 1
    assert _events(api, case_id)["total"] == 1


def test_case_deletion_removes_events(api: TestClient, run_jobs: RunJobs, engine: Engine) -> None:
    case_id = _case(api)
    _upload(api, case_id, AUTH, "auth.log")
    run_jobs()
    response = api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": "Parse"})
    assert response.status_code == 200
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(events)).scalar() == 0
        assert conn.execute(select(func.count()).select_from(raw_records)).scalar() == 0


def test_tampered_evidence_shows_unverified_record(
    api: TestClient, run_jobs: RunJobs, store: EvidenceStore
) -> None:
    case_id = _case(api)
    source = _upload(api, case_id, AUTH, "auth.log")["source_file"]
    run_jobs()
    path = store.blob_path(source["sha256"])
    path.chmod(0o644)
    path.write_bytes(AUTH.replace(b"Accepted", b"Rejected"))
    accepted = _events(api, case_id, event_type="logon")["items"][0]
    raw = api.get(f"/api/events/{accepted['event_id']}").json()["raw_record"]
    assert raw["verified"] is False
    assert "Rejected" in raw["text"]


def test_stored_copy_for_non_seekable_records(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case(api)
    _upload(api, case_id, (EVTX_SAMPLES / "new-user-security.evtx").read_bytes(), "Sec.evtx")
    run_jobs()
    event = _events(api, case_id, event_type="user_created")["items"][0]
    raw = api.get(f"/api/events/{event['event_id']}").json()["raw_record"]
    assert raw["source"] == "stored_copy"
    assert raw["encoding"] == "evtx-json-rendering"
    assert '"TargetUserName":"IEUser"' in raw["text"]


def test_unknown_event_is_404(api: TestClient) -> None:
    assert api.get("/api/events/nope").status_code == 404
