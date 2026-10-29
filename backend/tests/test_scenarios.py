"""Synthetic scenarios through the full pipeline: upload -> ingest -> parse."""

import importlib.util
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

GENERATOR = Path(__file__).resolve().parents[2] / "fixtures" / "generator" / "generate.py"
RunJobs = Callable[[], int]


@pytest.fixture(scope="module")
def scenarios(tmp_path_factory: pytest.TempPathFactory) -> Path:
    spec = importlib.util.spec_from_file_location("mizar_fixture_generator", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path_factory.mktemp("scenarios")
    module.generate(output)
    return output


def _ingest(api: TestClient, run_jobs: RunJobs, directory: Path) -> tuple[str, dict[str, Any]]:
    truth = json.loads((directory / "ground_truth.json").read_text())
    case_id = api.post(
        "/api/cases", json={"name": truth["scenario"], "analyst_name": "test"}
    ).json()["case_id"]
    for spec in truth["files"]:
        response = api.post(
            f"/api/cases/{case_id}/files",
            params={"filename": spec["path"], **spec.get("hints", {})},
            content=(directory / spec["path"]).read_bytes(),
        )
        assert response.status_code == 201, response.text
    run_jobs()
    return case_id, truth


def _files(api: TestClient, case_id: str) -> dict[str, Any]:
    files = api.get(f"/api/cases/{case_id}/files").json()
    return {f["archive_member_path"] or f["original_filename"]: f for f in files}


def _all_events(api: TestClient, case_id: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    while True:
        page = api.get(
            f"/api/cases/{case_id}/events", params={"limit": 500, "offset": len(items)}
        ).json()
        items.extend(page["items"])
        if len(items) >= page["total"]:
            return items


@pytest.mark.parametrize(
    "name", ["linux_intrusion", "web_intrusion", "windows_spray", "network_scan"]
)
def test_attack_scenarios_parse_completely(
    name: str, scenarios: Path, api: TestClient, run_jobs: RunJobs
) -> None:
    case_id, truth = _ingest(api, run_jobs, scenarios / name)
    files = _files(api, case_id)
    by_id = {f["source_file_id"]: path for path, f in files.items()}
    for spec in truth["files"]:
        row = files[spec.get("archive_member", spec["path"])]
        assert row["effective_format"] == spec["expected_format"], row["detection_candidates"]
        assert row["parse"]["status"] == "succeeded", row["parse"]
        assert row["parse"]["records_unparsed"] == 0
        assert row["parse"]["records_partial"] == 0

    events = _all_events(api, case_id)
    counts = Counter(f"{by_id[e['source_file_id']]}:{e['event_type']}" for e in events)
    for key, expected in truth["counts"].items():
        file_name, event_type = key.split(":")
        member = next(
            (s.get("archive_member", s["path"]) for s in truth["files"] if s["path"] == file_name),
            file_name,
        )
        assert counts[f"{member}:{event_type}"] == expected, key
    assert all(e["timestamp_utc"] is not None for e in events)


def test_hostile_inputs_are_contained(scenarios: Path, api: TestClient, run_jobs: RunJobs) -> None:
    case_id, _ = _ingest(api, run_jobs, scenarios / "hostile_inputs")
    files = _files(api, case_id)

    archive = files["evidence.zip"]
    codes = [m["code"] for m in archive["validation_messages"]]
    assert codes.count("ARCHIVE_PATH_TRAVERSAL") == 2
    assert "ARCHIVE_BOMB_SUSPECTED" in codes
    assert files["logs/ok.log"]["parse"]["records_total"] == 1

    hostile = files["hostile.log"]
    assert hostile["parse"]["records_total"] == 5
    assert hostile["parse"]["warnings_by_code"]["truncated_record"] == 1
    assert hostile["parse"]["warnings_by_code"]["encoding_replaced"] == 1
    events = api.get(
        f"/api/cases/{case_id}/events", params={"source_file_id": hostile["source_file_id"]}
    ).json()["items"]
    script = next(e for e in events if e["event_type"] == "logon_failed")
    # Stored verbatim: escaping is the job of every renderer (UI, PDF, CSV export).
    assert script["username"] == "<script>alert(1)</script>"

    csv_events = api.get(
        f"/api/cases/{case_id}/events",
        params={"source_file_id": files["eventviewer.csv"]["source_file_id"]},
    ).json()["items"]
    warnings = {e["message"]: e for e in csv_events}
    assert warnings["Ambiguous (DST fall-back)"]["timestamp_utc"] is None
    assert "dst_ambiguous" in warnings["Ambiguous (DST fall-back)"]["parse_warnings"]
    assert "dst_nonexistent" in warnings["Nonexistent (DST spring-forward)"]["parse_warnings"]
    assert warnings["Normal"]["timestamp_utc"].startswith("2026-10-29T13:00:00")
