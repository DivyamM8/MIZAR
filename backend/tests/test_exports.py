import csv
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from mizar.core.config import Settings
from mizar.detection.rules import BANNED_WORDING
from mizar.reporting import service as export_service
from mizar.reporting.text import csv_cell, para, visible

from .analysis_helpers import RunJobs, analyze, by_rule, new_case, upload

T0 = datetime(2026, 10, 27, 8, 0, tzinfo=UTC)
HINTS = {"timezone_hint": "UTC", "year_hint": 2026}
HOSTILE_NOTE = (
    '<b>bold</b><img src="file:///etc/passwd"/> &amp; =SUM(A1) Привет '
    "Grüße Łódź 中文 של invoice‮fdp.exe \x07"
)


def _auth_log() -> bytes:
    lines = [
        f"{(T0 + timedelta(seconds=i)):%b %d %H:%M:%S} srv01 sshd[{50 + i}]: Failed password for root "
        f"from 203.0.113.7 port {40000 + i} ssh2"
        for i in range(25)
    ]
    lines.append(
        f"{(T0 + timedelta(seconds=40)):%b %d %H:%M:%S} srv01 sshd[99]: Accepted password for root "
        "from 203.0.113.7 port 41000 ssh2"
    )
    lines.append(
        f"{(T0 + timedelta(minutes=2)):%b %d %H:%M:%S} srv01 useradd[5]: new user: name=svc2, UID=1500"
    )
    return ("\n".join(lines) + "\n").encode()


def _analyzed(api: TestClient, run_jobs: RunJobs, name: str = "Exports") -> tuple[str, str, list]:
    case_id = new_case(api, name)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run, found = analyze(api, run_jobs, case_id)
    assert run["status"] == "succeeded" and found
    return case_id, run["run_id"], found


def _export(api: TestClient, run_jobs: RunJobs, run_id: str, **body: Any) -> dict[str, Any]:
    response = api.post(f"/api/runs/{run_id}/exports", json=body)
    assert response.status_code == 202, response.text
    run_jobs()
    export = api.get(f"/api/exports/{response.json()['export_id']}").json()
    assert export["status"] == "succeeded", export
    return export


def _download(api: TestClient, export: dict[str, Any]) -> bytes:
    response = api.get(f"/api/exports/{export['export_id']}/download")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["content-type"].startswith(export["media_type"])
    assert hashlib.sha256(response.content).hexdigest() == export["sha256"]
    assert len(response.content) == export["size_bytes"]
    return response.content


def _no_partials(settings: Settings) -> None:
    assert not list(settings.exports_dir.rglob("*.partial"))


def _pdf_text(data: bytes) -> tuple[str, PdfReader]:
    reader = PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() for page in reader.pages), reader


def test_pdf_report(api: TestClient, run_jobs: RunJobs, settings: Settings) -> None:
    case_id, run_id, found = _analyzed(api, run_jobs, "Case <i>Alpha</i>")
    target = found[0]["finding_id"]
    patched = api.patch(
        f"/api/findings/{target}", json={"status": "investigating", "analyst_notes": HOSTILE_NOTE}
    )
    assert patched.status_code == 200
    export = _export(api, run_jobs, run_id, format="pdf", marking="final")
    assert export["media_type"] == "application/pdf"
    text, reader = _pdf_text(_download(api, export))

    for heading in (
        "Investigation report",
        "2. Executive summary",
        "3. Scope and evidence",
        "4. Methodology",
        "5. Findings",
        "6. Timeline of finding-related events",
        "7. Entities in findings",
        "8. Limitations and assumptions",
        "9. Appendix: run manifest",
    ):
        assert heading in text, heading
    assert "Case <i>Alpha</i>" in text  # drawn as text, not interpreted
    assert "FINAL" in text and "MIZAR" in text
    pages = len(reader.pages)
    assert f"Page 1 of {pages}" in text and f"Page {pages} of {pages}" in text
    assert f"Run {run_id}" in text and case_id in text
    for finding in found:
        assert finding["finding_id"] in text
    # Hostile analyst notes: markup shown literally, unsupported characters escaped.
    assert "<b>bold</b><img" in text.replace("\n", "")
    flat = text.replace("\n", "")
    assert "\u041f\u0440\u0438\u0432\u0435\u0442" in flat  # Cyrillic drawn by the fallback font
    assert "\u0141\u00f3d\u017a" in flat and "Gr\u00fc\u00dfe" in flat
    assert "\\u{4e2d}\\u{6587}" in flat  # no glyphs: escaped
    assert "\\u{05e9}\\u{05dc}" in flat  # right-to-left: escaped
    assert "invoice\\u{202e}fdp.exe" in flat  # the override is made visible
    assert "\\x07" in flat
    assert "srv01" in text and "203.0.113.7" in text
    meta = reader.metadata
    assert meta is not None and meta.creator == "MIZAR 0.1.0"
    assert meta.author == "R. Analyst"
    assert export["summary"]["findings"] == len(found)
    assert export["summary"]["pages"] == pages
    _no_partials(settings)
    stored = settings.exports_dir / case_id / f"{export['export_id']}.pdf"
    assert stored.stat().st_mode & 0o777 == 0o400


def test_pdf_evidence_is_truncated_with_a_pointer(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, found = _analyzed(api, run_jobs)
    export = _export(api, run_jobs, run_id, format="pdf", evidence_limit=3)
    text, _ = _pdf_text(_download(api, export))
    biggest = max(found, key=lambda f: f["event_count"])
    assert f"Showing 3 of {biggest['event_count']} linked events" in text.replace("\n", " ")
    assert "DRAFT" in text


def test_json_export(api: TestClient, run_jobs: RunJobs) -> None:
    case_id, run_id, found = _analyzed(api, run_jobs)
    export = _export(api, run_jobs, run_id, format="json")
    assert export["media_type"] == "application/json"
    doc = json.loads(_download(api, export))
    assert doc["export_format"] == "mizar.report"
    assert doc["event_schema_version"] == "1.0.0"
    assert doc["case"]["case_id"] == case_id
    assert doc["run"]["run_id"] == run_id
    assert doc["run"]["manifest"]["inputs"][0]["filename"] == "auth.log"
    assert [f["finding_id"] for f in doc["findings"]] == [f["finding_id"] for f in found]
    sequence = by_rule(doc["findings"], "AUTH-003")[0]
    assert len(sequence["evidence"]) == 26 and all(e["present"] for e in sequence["evidence"])
    referenced = {e["event_id"] for f in doc["findings"] for e in f["evidence"]}
    assert {e["event_id"] for e in doc["events"]} == referenced
    for event in doc["events"]:
        assert event["raw_record"]["verified"] is True
        assert (
            event["raw_record"]["text"].endswith("ssh2") or "useradd" in event["raw_record"]["text"]
        )
        assert event["parser_version"] and event["schema_version"] == "1.0.0"
    assert doc["source_files"][0]["sha256"] == doc["run"]["manifest"]["inputs"][0]["sha256"]
    assert doc["summary"]["findings_included"] == len(found)
    assert "all_events" not in doc


def test_json_with_all_events(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, _ = _analyzed(api, run_jobs)
    export = _export(api, run_jobs, run_id, format="json", all_events=True)
    assert export["media_type"] == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(_download(api, export)))
    assert sorted(archive.namelist()) == ["events.ndjson", "report.json"]
    doc = json.loads(archive.read("report.json"))
    lines = [json.loads(line) for line in archive.read("events.ndjson").splitlines()]
    assert len(lines) == doc["summary"]["events_total"] == 27
    stamps = [e["timestamp_utc"] for e in lines]
    assert stamps == sorted(stamps)
    assert export["summary"]["all_events"] == 27


def test_csv_bundle_neutralizes_formulas(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, found = _analyzed(api, run_jobs)
    target = found[0]["finding_id"]
    api.patch(f"/api/findings/{target}", json={"analyst_notes": '=HYPERLINK("http://x")'})
    export = _export(api, run_jobs, run_id, format="csv")
    archive = zipfile.ZipFile(io.BytesIO(_download(api, export)))
    assert sorted(archive.namelist()) == [
        "events.csv",
        "export.json",
        "findings.csv",
        "source_files.csv",
    ]
    tables = {}
    for name in ("findings.csv", "events.csv", "source_files.csv"):
        raw = archive.read(name)
        assert raw.startswith(b"\xef\xbb\xbf")
        tables[name] = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    findings_rows = tables["findings.csv"]
    assert len(findings_rows) == len(found)
    note = next(r for r in findings_rows if r["finding_id"] == target)["analyst_notes"]
    assert note == '\'=HYPERLINK("http://x")'
    for rows in tables.values():
        for row in rows:
            for value in row.values():
                assert not value.startswith(("=", "+", "-", "@", "\t", "\r")), value
    events_rows = tables["events.csv"]
    assert events_rows and all(r["finding_ids"] for r in events_rows)
    assert tables["source_files.csv"][0]["filename"] == "auth.log"
    assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())


def test_filters(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, found = _analyzed(api, run_jobs)
    dismissed = found[0]["finding_id"]
    api.patch(f"/api/findings/{dismissed}", json={"status": "false_positive"})
    statuses = ["open", "investigating", "confirmed", "resolved"]
    export = _export(api, run_jobs, run_id, format="json", statuses=statuses)
    doc = json.loads(_download(api, export))
    assert dismissed not in {f["finding_id"] for f in doc["findings"]}
    assert doc["summary"]["findings_excluded"] == {"by_status": 1, "by_severity": 0}
    assert doc["summary"]["findings_in_run"][found[0]["severity"]]["false_positive"] == 1

    high = _export(api, run_jobs, run_id, format="json", min_severity="high")
    doc = json.loads(_download(api, high))
    assert all(f["severity"] in ("high", "critical") for f in doc["findings"])
    below = sum(f["severity"] not in ("high", "critical") for f in found)
    assert doc["summary"]["findings_excluded"]["by_severity"] == below

    pdf = _export(api, run_jobs, run_id, format="pdf", statuses=statuses)
    text, _ = _pdf_text(_download(api, pdf))
    flat = text.replace("\n", " ")
    assert "1 excluded by the export filters (1 by status" in flat
    assert dismissed not in text


def test_export_list_and_delete(api: TestClient, run_jobs: RunJobs, settings: Settings) -> None:
    case_id, run_id, _ = _analyzed(api, run_jobs)
    first = _export(api, run_jobs, run_id, format="json")
    second = _export(api, run_jobs, run_id, format="csv")
    listed = api.get(f"/api/runs/{run_id}/exports").json()
    assert [e["export_id"] for e in listed] == [second["export_id"], first["export_id"]]
    path = settings.exports_dir / case_id / f"{first['export_id']}.json"
    assert path.is_file()
    deleted = api.delete(f"/api/exports/{first['export_id']}")
    assert deleted.status_code == 200 and not path.exists()
    assert api.get(f"/api/exports/{first['export_id']}").status_code == 404
    assert api.get(f"/api/runs/{run_id}/exports").json()[0]["export_id"] == second["export_id"]


def test_export_requests_are_validated(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, _ = _analyzed(api, run_jobs)
    for body in (
        {"format": "docx"},
        {"format": "pdf", "statuses": []},
        {"format": "pdf", "statuses": ["done"]},
        {"format": "pdf", "evidence_limit": 0},
        {"format": "pdf", "all_events": True},
        {"format": "pdf", "unexpected": 1},
    ):
        response = api.post(f"/api/runs/{run_id}/exports", json=body)
        assert response.status_code == 422, body
    assert api.post("/api/runs/RUN-nope/exports", json={"format": "pdf"}).status_code == 404
    assert api.get("/api/exports/EXP-nope").status_code == 404
    assert api.get("/api/exports/EXP-nope/download").status_code == 404


def test_unfinished_run_cannot_be_exported(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run_jobs()
    started = api.post(f"/api/cases/{case_id}/runs", json={}).json()
    response = api.post(f"/api/runs/{started['run_id']}/exports", json={"format": "pdf"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "RUN_NOT_FINISHED"


def test_queued_export(api: TestClient, run_jobs: RunJobs, settings: Settings) -> None:
    _, run_id, _ = _analyzed(api, run_jobs)
    started = api.post(f"/api/runs/{run_id}/exports", json={"format": "pdf"}).json()
    early = api.get(f"/api/exports/{started['export_id']}/download")
    assert early.status_code == 409 and early.json()["error"]["code"] == "EXPORT_NOT_READY"
    busy = api.delete(f"/api/exports/{started['export_id']}")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "EXPORT_BUSY"
    assert api.post(f"/api/jobs/{started['job_id']}/cancel").status_code == 200
    run_jobs()
    export = api.get(f"/api/exports/{started['export_id']}").json()
    assert export["status"] == "cancelled"
    _no_partials(settings)
    assert api.delete(f"/api/exports/{started['export_id']}").status_code == 200


def test_render_failure_leaves_no_file(
    api: TestClient, run_jobs: RunJobs, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id, run_id, _ = _analyzed(api, run_jobs)

    def broken(path: Path, data: Any, check: Any) -> dict[str, int]:
        path.write_bytes(b"%PDF-partial")
        raise RuntimeError("layout exploded")

    monkeypatch.setattr(export_service, "render_pdf", broken)
    started = api.post(f"/api/runs/{run_id}/exports", json={"format": "pdf"}).json()
    run_jobs()
    export = api.get(f"/api/exports/{started['export_id']}").json()
    assert export["status"] == "failed"
    assert export["error_code"] == "REPORT_RENDER_FAILED"
    assert "layout exploded" not in export["error_message"]
    assert not [p for p in (settings.exports_dir / case_id).iterdir()]


def test_case_deletion_removes_exports(
    api: TestClient, run_jobs: RunJobs, settings: Settings
) -> None:
    case_id, run_id, _ = _analyzed(api, run_jobs, "Doomed")
    export = _export(api, run_jobs, run_id, format="pdf")
    response = api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": "Doomed"})
    assert response.status_code == 200
    assert not (settings.exports_dir / case_id).exists()
    assert api.get(f"/api/exports/{export['export_id']}").status_code == 404


def test_report_wording_does_not_overstate(api: TestClient, run_jobs: RunJobs) -> None:
    _, run_id, _ = _analyzed(api, run_jobs)
    export = _export(api, run_jobs, run_id, format="pdf")
    text, _ = _pdf_text(_download(api, export))
    # Rule texts are linted separately; this checks the report's own sentences.
    # "Confirmed" is allowed only as the name of the analyst status (a table heading).
    found = [w for w in BANNED_WORDING.findall(text) if w != "Confirmed"]
    assert not found, found
    assert text.count("Confirmed") == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("-2", "'-2"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        ("\rx", "'\rx"),
        ("plain", "plain"),
        (-2, -2),
        (None, ""),
        (["=a", "b"], "'=a; b"),
    ],
)
def test_csv_cell(value: Any, expected: Any) -> None:
    assert csv_cell(value) == expected


def test_pdf_text_escaping() -> None:
    assert para("<b>&</b>") == "&lt;b&gt;&amp;&lt;/b&gt;"
    assert para("a\nb") == "a<br/>b"
    assert visible("café €") == "café €"  # in cp1252
    assert visible("中\x00\x9b") == "\\u{4e2d}\\x00\\x9b"
    assert visible("Ж Ω א a​b") == "Ж Ω \\u{05d0} a\\u{200b}b"
    assert para("Жx") == '<font name="MizarFallback">Ж</font>x'
    assert para("x" * 10, limit=4) == "xxxx [... 6 more characters]"
