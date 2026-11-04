from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, delete, func, select

from mizar.db.tables import analysis_runs, events, finding_events, findings
from mizar.detection.engine import Detector
from mizar.evidence.store import EvidenceStore

from .analysis_helpers import RunJobs, analyze, by_rule, new_case, upload

T0 = datetime(2026, 10, 27, 8, 0, tzinfo=UTC)
HINTS = {"timezone_hint": "UTC", "year_hint": 2026}


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


def _error(response: Any) -> str:
    return str(response.json()["error"]["code"])


def test_run_refused_without_ready_inputs(api: TestClient) -> None:
    case_id = new_case(api)
    empty = api.post(f"/api/cases/{case_id}/runs", json={})
    assert empty.status_code == 409 and _error(empty) == "RUN_INPUTS_NOT_READY"
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)  # ingest job not run yet
    pending = api.post(f"/api/cases/{case_id}/runs", json={})
    assert pending.status_code == 409 and _error(pending) == "RUN_INPUTS_NOT_READY"


@pytest.mark.parametrize(
    "overrides",
    [
        {"NOPE-001": {}},
        {"AUTH-001": {"min_failures": 0}},
        {"AUTH-001": {"nope": 3}},
        {"AUTH-001": {"window": "soon"}},
    ],
)
def test_invalid_overrides(api: TestClient, run_jobs: RunJobs, overrides: dict[str, Any]) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run_jobs()
    response = api.post(f"/api/cases/{case_id}/runs", json={"overrides": overrides})
    assert response.status_code == 422 and _error(response) == "RULE_PARAM_INVALID"


def test_runs_are_reproducible_and_recorded(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    source = upload(api, case_id, _auth_log(), "auth.log", **HINTS)["source_file"]
    first, first_findings = analyze(api, run_jobs, case_id)
    second, second_findings = analyze(api, run_jobs, case_id)

    assert first["status"] == second["status"] == "succeeded"
    assert first["inputs_fingerprint"] == second["inputs_fingerprint"]
    assert first["manifest_sha256"] != second["manifest_sha256"]  # includes run ID and time

    def comparable(items: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
        return [
            (
                f["finding_id"].rsplit("-", 1)[1],
                f["fingerprint"],
                f["title"],
                f["severity"],
                f["confidence"],
                f["event_count"],
            )
            for f in items
        ]

    assert comparable(first_findings) == comparable(second_findings)
    assert {f["rule_id"] for f in first_findings} >= {"AUTH-001", "AUTH-003", "PERS-001"}

    manifest = api.get(f"/api/runs/{first['run_id']}").json()["manifest"]
    (entry,) = manifest["inputs"]
    assert entry["sha256"] == source["sha256"]
    assert (entry["parser_name"], entry["parser_version"], entry["timezone_hint"]) == (
        "linux.syslog",
        "1.0.0",
        "UTC",
    )
    assert len(manifest["rules"]) == 32 and all(
        len(r["rule_file_sha256"]) == 64 for r in manifest["rules"]
    )
    assert manifest["params"]["AUTH-001"] == {"min_failures": 20, "window": "10m"}
    assert manifest["event_schema_version"] == "1.0.0"
    results = first["results"]
    assert results["events_evaluated"] == 27
    assert results["evidence_verification"]["verified"] == 1
    listed = api.get(f"/api/cases/{case_id}/runs").json()
    assert [r["run_id"] for r in listed] == [second["run_id"], first["run_id"]]


def test_tampered_evidence_blocks_the_run(
    api: TestClient, run_jobs: RunJobs, store: EvidenceStore
) -> None:
    case_id = new_case(api)
    source = upload(api, case_id, _auth_log(), "auth.log", **HINTS)["source_file"]
    run_jobs()
    path = store.blob_path(source["sha256"])
    path.chmod(0o644)
    path.write_bytes(b"replaced\n")
    run, found = analyze(api, run_jobs, case_id)
    assert (run["status"], run["error_code"]) == ("failed", "EVIDENCE_INTEGRITY_MISMATCH")
    assert run["results"]["error_details"]["failures"][0]["status"] == "integrity_failed"
    assert found == []


def test_analyst_status_carries_to_the_next_run(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    _, findings_before = analyze(api, run_jobs, case_id)
    target = by_rule(findings_before, "AUTH-003")[0]
    updated = api.patch(
        f"/api/findings/{target['finding_id']}",
        json={"status": "investigating", "analyst_notes": "Owner says not them."},
    )
    assert updated.status_code == 200, updated.text
    assert (updated.json()["updated_by"], updated.json()["status"]) == (
        "R. Analyst",
        "investigating",
    )

    _, findings_after = analyze(api, run_jobs, case_id)
    carried = by_rule(findings_after, "AUTH-003")[0]
    assert carried["fingerprint"] == target["fingerprint"]
    assert (carried["status"], carried["analyst_notes"]) == (
        "investigating",
        "Owner says not them.",
    )
    assert carried["status_carried_from"] == target["finding_id"]
    untouched = by_rule(findings_after, "AUTH-001")[0]
    assert (untouched["status"], untouched["status_carried_from"]) == ("open", None)


@pytest.mark.parametrize(
    "body",
    [{"status": "done"}, {"status": None}, {"unexpected": 1}, {"analyst_notes": "x" * 20_001}],
)
def test_finding_update_validation(
    api: TestClient, run_jobs: RunJobs, body: dict[str, Any]
) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    _, found = analyze(api, run_jobs, case_id)
    response = api.patch(f"/api/findings/{found[0]['finding_id']}", json=body)
    assert response.status_code == 422


def test_finding_detail_links_evidence(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    _, found = analyze(api, run_jobs, case_id)
    sequence = by_rule(found, "AUTH-003")[0]
    detail = api.get(f"/api/findings/{sequence['finding_id']}").json()
    roles = [e["role"] for e in detail["evidence_events"]]
    assert roles.count("failures") == 25 and roles[-1] == "success"
    assert detail["evidence_total"] == 26
    assert all(e["present"] for e in detail["evidence_events"])
    assert detail["evidence_events"][-1]["username"] == "root"
    assert detail["observed_evidence"]["failures_count"] == 25
    assert detail["verification_steps"] and detail["alternative_explanations"]
    texts = [*detail["verification_steps"], *detail["alternative_explanations"]]
    assert not [t for t in texts if "{" in t], "placeholders must be filled in"
    assert "consistent with" in detail["interpretation"]
    page = api.get(f"/api/findings/{sequence['finding_id']}", params={"offset": 20}).json()
    assert len(page["evidence_events"]) == 6
    assert api.get("/api/findings/nope").status_code == 404
    assert api.get("/api/runs/nope").status_code == 404


def test_findings_are_in_priority_order(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run, found = analyze(api, run_jobs, case_id)
    order = ["critical", "high", "medium", "low", "informational"]
    assert [order.index(f["severity"]) for f in found] == sorted(
        order.index(f["severity"]) for f in found
    )
    high = api.get(f"/api/runs/{run['run_id']}/findings", params={"severity": "high"}).json()
    assert high and all(f["severity"] == "high" for f in high)


def test_failing_rule_does_not_stop_the_run(
    api: TestClient, run_jobs: RunJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Detector._threshold

    def broken(self: Detector, rule: Any) -> Any:
        if rule.id == "AUTH-001":
            raise RuntimeError("simulated rule bug")
        return original(self, rule)

    monkeypatch.setattr(Detector, "_threshold", broken)
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run, found = analyze(api, run_jobs, case_id)
    assert run["status"] == "succeeded_with_errors"
    assert run["results"]["rule_errors"] == [
        {"rule_id": "AUTH-001", "error": "RuntimeError", "message": "simulated rule bug"}
    ]
    assert by_rule(found, "AUTH-003") and not by_rule(found, "AUTH-001")


def test_cancelled_queued_run_is_reported_cancelled(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    run_jobs()
    started = api.post(f"/api/cases/{case_id}/runs", json={}).json()
    assert api.post(f"/api/jobs/{started['job_id']}/cancel").status_code == 200
    run_jobs()
    assert api.get(f"/api/runs/{started['run_id']}").json()["status"] == "cancelled"


def test_coverage_gaps_and_stale_evidence(
    api: TestClient, run_jobs: RunJobs, engine: Engine
) -> None:
    case_id = new_case(api)
    source = upload(api, case_id, _auth_log(), "auth.log", timezone_hint="UTC")[
        "source_file"
    ]  # no year
    upload(api, case_id, b"free text without structure\n", "notes.txt")
    run, found = analyze(api, run_jobs, case_id)
    reasons = " ".join(g["reason"] for g in run["results"]["coverage_gaps"])
    assert "No specific parser" in reasons
    assert "no reliable UTC time" in reasons
    assert run["results"]["rule_notes"]["AUTH-001"]["events_without_utc_skipped"] == 25
    assert not by_rule(found, "AUTH-001")  # time windows need UTC times
    created = by_rule(found, "PERS-001")[0]  # single-event rules still apply

    api.post(
        f"/api/cases/{case_id}/files/{source['source_file_id']}/reparse",
        json={"format_override": "generic_text"},
    )
    run_jobs()
    # Event IDs identify records, not interpretations: re-parsing the same bytes keeps them,
    # so the old finding still points at the same original record.
    detail = api.get(f"/api/findings/{created['finding_id']}").json()
    assert detail["evidence_events"][0]["present"] is True

    with engine.begin() as conn:
        conn.execute(delete(events).where(events.c.source_file_id == source["source_file_id"]))
    detail = api.get(f"/api/findings/{created['finding_id']}").json()
    assert detail["evidence_events"][0]["present"] is False  # links survive; absence is shown


def test_case_deletion_removes_runs(api: TestClient, run_jobs: RunJobs, engine: Engine) -> None:
    case_id = new_case(api, name="Gone")
    upload(api, case_id, _auth_log(), "auth.log", **HINTS)
    analyze(api, run_jobs, case_id)
    assert (
        api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": "Gone"}).status_code
        == 200
    )
    with engine.connect() as conn:
        for table in (analysis_runs, findings, finding_events):
            assert conn.execute(select(func.count()).select_from(table)).scalar() == 0


def test_rule_catalogue(api: TestClient) -> None:
    rules = api.get("/api/rules").json()
    assert len(rules) == 32
    auth = next(r for r in rules if r["rule_id"] == "AUTH-001")
    assert auth["params"]["min_failures"]["default"] == 20
    assert auth["attack"] == ["T1110.001"]
