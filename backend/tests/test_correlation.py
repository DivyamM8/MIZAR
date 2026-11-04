from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from .analysis_helpers import RunJobs, analyze, new_case, upload
from .test_parsers import EVTX_SAMPLES

T0 = datetime(2026, 10, 27, 8, 0, tzinfo=UTC)
HINTS = {"timezone_hint": "UTC", "year_hint": 2026}


def _line(ts: datetime, text: str, host: str = "srv01") -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} {text}\n"


def _ssh_session(start: datetime, pid: int, user: str, ip: str) -> str:
    return (
        _line(start, f"sshd[{pid}]: Accepted password for {user} from {ip} port 5000 ssh2")
        + _line(
            start,
            f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)",
        )
        + _line(
            start + timedelta(minutes=5),
            f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}",
        )
    )


AUTH = (
    "".join(
        _line(
            T0 + timedelta(seconds=i),
            f"sshd[{100 + i}]: Failed password for root from 203.0.113.7 port {4000 + i} ssh2",
        )
        for i in range(25)
    )
    + _ssh_session(T0 + timedelta(minutes=1), 900, "root", "203.0.113.7")
    + _line(T0 + timedelta(minutes=2), "useradd[5]: new user: name=svc2, UID=1500")
    + _ssh_session(T0 + timedelta(hours=3), 901, "alice", "10.0.0.5")
).encode()


def _all(api: TestClient, case_id: str, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        query = {"limit": 7, **params, **({"after": cursor} if cursor else {})}
        response = api.get(f"/api/cases/{case_id}/timeline", params=query)
        assert response.status_code == 200, response.text
        page = response.json()
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            return items


def _case_with_auth(api: TestClient, run_jobs: RunJobs, data: bytes = AUTH) -> str:
    case_id = new_case(api)
    upload(api, case_id, data, "auth.log", **HINTS)
    analyze(api, run_jobs, case_id)
    return case_id


def test_timeline_keyset_paging_is_complete_and_ordered(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    events = _all(api, case_id)
    total = api.get(f"/api/cases/{case_id}/events").json()["total"]
    assert len(events) == total == 32
    assert len({e["event_id"] for e in events}) == total
    keys = [(e["timestamp_utc"], e["source_file_id"], e["record_index"]) for e in events]
    assert keys == sorted(keys)
    assert events[0]["source_filename"] == "auth.log"


def test_timeline_backward_paging(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    first = api.get(f"/api/cases/{case_id}/timeline", params={"limit": 10}).json()
    assert first["prev_cursor"] is None
    second = api.get(
        f"/api/cases/{case_id}/timeline", params={"limit": 10, "after": first["next_cursor"]}
    ).json()
    back = api.get(
        f"/api/cases/{case_id}/timeline", params={"limit": 10, "before": second["prev_cursor"]}
    ).json()
    assert [e["event_id"] for e in back["items"]] == [e["event_id"] for e in first["items"]]
    assert back["prev_cursor"] is None and back["next_cursor"] is not None


def test_unplaced_lane_and_cursor_validation(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, AUTH, "auth.log", timezone_hint="UTC")  # no year: nothing placed
    upload(api, case_id, AUTH, "auth2.log", **HINTS)
    run_jobs()
    placed = api.get(f"/api/cases/{case_id}/timeline", params={"limit": 500}).json()
    unplaced = api.get(
        f"/api/cases/{case_id}/timeline", params={"lane": "unplaced", "limit": 5}
    ).json()
    assert {e["source_filename"] for e in placed["items"]} == {"auth2.log"}
    assert all(e["timestamp_utc"] is None for e in unplaced["items"])
    assert [e["record_index"] for e in unplaced["items"]] == [0, 1, 2, 3, 4]
    wrong_lane = api.get(
        f"/api/cases/{case_id}/timeline",
        params={"lane": "placed", "after": unplaced["next_cursor"]},
    )
    assert wrong_lane.status_code == 422
    for params in (
        {"after": "garbage!"},
        {"after": "x", "before": "y"},
        {"start": "2026-10-27T08:00:00"},
        {"min_severity": "huge"},
    ):
        assert api.get(f"/api/cases/{case_id}/timeline", params=params).status_code == 422


def test_timeline_filters_and_finding_markers(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    by_ip = _all(api, case_id, ip="10.0.0.5")
    assert len(by_ip) == 1 and by_ip[0]["event_type"] == "logon"
    high = _all(api, case_id, min_severity="high")
    assert high and all(
        any(f["severity"] in ("high", "critical") for f in e["findings"]) for e in high
    )
    marked = [e for e in _all(api, case_id) if e["findings"]]
    assert any(f["rule_id"] == "AUTH-001" for e in marked for f in e["findings"])
    finding_id = next(
        f["finding_id"] for e in marked for f in e["findings"] if f["rule_id"] == "PERS-001"
    )
    only = _all(api, case_id, finding_id=finding_id)
    assert [e["event_type"] for e in only] == ["user_created"]
    window = _all(api, case_id, start="2026-10-27T11:00:00Z")
    assert {e["username"] for e in window} == {"alice"}


def test_histogram(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    histogram = api.get(f"/api/cases/{case_id}/timeline/histogram", params={"buckets": 12}).json()
    assert histogram["bucket_seconds"] == 1800  # 3h05m span / 12 = 925s -> next nice size, 30m
    assert sum(b["count"] for b in histogram["buckets"]) == histogram["placed"] == 32
    assert histogram["unplaced"] == 0
    assert histogram["buckets"][0]["finding_events"] > 0
    empty = api.get(f"/api/cases/{new_case(api)}/timeline/histogram").json()
    assert empty["buckets"] == [] and empty["placed"] == 0


def test_ssh_sessions_and_gap_split(api: TestClient, run_jobs: RunJobs) -> None:
    reused = _ssh_session(T0, 4242, "bob", "10.0.0.9") + _ssh_session(
        T0 + timedelta(days=2), 4242, "carol", "10.0.0.8"
    )
    case_id = _case_with_auth(api, run_jobs, AUTH + reused.encode())
    sessions = api.get(f"/api/cases/{case_id}/sessions").json()
    by_user = {tuple(s["usernames"]): s for s in sessions["items"]}
    assert by_user[("bob",)]["session_id"] == by_user[("carol",)]["session_id"] == "sshd[4242]"
    assert by_user[("bob",)]["session_group_id"] != by_user[("carol",)]["session_group_id"]
    root = by_user[("root",)]
    assert (root["event_count"], root["closed"], root["first_event_type"]) == (3, True, "logon")
    assert all(s["event_count"] >= 2 for s in sessions["items"])  # one-line "sessions" are skipped
    detail = api.get(f"/api/sessions/{root['session_group_id']}").json()
    assert [e["event_type"] for e in detail["events"]] == [
        "logon",
        "session_opened",
        "session_closed",
    ]
    assert (
        api.get(f"/api/cases/{case_id}/sessions", params={"username": "alice"}).json()["total"] == 1
    )
    assert (
        api.get(f"/api/cases/{case_id}/sessions", params={"ip": "203.0.113.7"}).json()["total"] == 1
    )
    assert api.get("/api/sessions/SES-nope").status_code == 404


def test_windows_logon_session_excludes_shared_system_ids(
    api: TestClient, run_jobs: RunJobs, scenarios: Path
) -> None:
    case_id = new_case(api)
    upload(
        api,
        case_id,
        (scenarios / "windows_spray" / "Security-export.xml").read_bytes(),
        "Security.xml",
    )
    analyze(api, run_jobs, case_id)
    (session,) = api.get(f"/api/cases/{case_id}/sessions").json()["items"]
    assert session["session_id"] == "0x8a3f21"
    types = [t for t, _ in session["event_types"]]
    assert {
        "logon",
        "special_privileges_assigned",
        "user_created",
        "group_member_added",
        "audit_log_cleared",
    } <= set(types)
    assert session["source_ips"] == ["198.51.100.77"]


def test_duplicates_do_not_double_sessions_or_entities(api: TestClient, run_jobs: RunJobs) -> None:
    single = _case_with_auth(api, run_jobs)
    double = new_case(api)
    upload(api, double, AUTH, "auth.log", **HINTS)
    upload(api, double, AUTH, "auth.log.copy", **HINTS)
    analyze(api, run_jobs, double)

    def summary(case_id: str) -> Any:
        ents = api.get(f"/api/cases/{case_id}/entities").json()["items"]
        sess = api.get(f"/api/cases/{case_id}/sessions").json()["items"]
        return sorted((e["entity_type"], e["value"], e["event_count"]) for e in ents), sorted(
            s["event_count"] for s in sess
        )

    assert summary(single) == summary(double)


def test_entities(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    page = api.get(f"/api/cases/{case_id}/entities").json()
    assert page["index"]["status"] == "current"
    entities = {(e["entity_type"], e["value"]): e for e in page["items"]}
    attacker = entities[("ip", "203.0.113.7")]
    assert (attacker["event_count"], attacker["as_source"], attacker["as_destination"]) == (
        26,
        26,
        0,
    )
    assert attacker["finding_count"] >= 2 and attacker["highest_severity"] in ("high", "critical")
    assert entities[("host", "srv01")]["event_count"] == 32
    assert entities[("user", "alice")]["first_seen_utc"].startswith("2026-10-27T11:00:00")
    ips = api.get(f"/api/cases/{case_id}/entities", params={"type": "ip", "q": "10.0"}).json()
    assert [e["value"] for e in ips["items"]] == ["10.0.0.5"]

    detail = api.get(
        f"/api/cases/{case_id}/entity", params={"type": "user", "value": "root"}
    ).json()
    assert {"AUTH-001", "AUTH-003"} & {f["rule_id"] for f in detail["findings"]}
    assert len(detail["sessions"]) == 1
    assert (
        api.get(
            f"/api/cases/{case_id}/entity", params={"type": "user", "value": "nobody"}
        ).status_code
        == 404
    )
    assert api.get(f"/api/cases/{case_id}/entities", params={"type": "planet"}).status_code == 422


def test_related_events_are_labeled_not_causal(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = _case_with_auth(api, run_jobs)
    logon = _all(api, case_id, ip="10.0.0.5")[0]
    related = api.get(
        f"/api/events/{logon['event_id']}/related", params={"field": "username", "window": "10m"}
    ).json()
    assert {e["event_type"] for e in related["items"]} == {"session_opened", "session_closed"}
    assert "does not show that one event caused another" in related["note"]
    assert related["basis"] == {"field": "username", "value": "alice", "window_seconds": 600}
    for params in ({"field": "message"}, {"window": "soon"}):
        assert api.get(f"/api/events/{logon['event_id']}/related", params=params).status_code == 422


def test_sysmon_process_links(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    upload(api, case_id, (EVTX_SAMPLES / "sysmon.evtx").read_bytes(), "sysmon.evtx")
    run_jobs()
    created = api.get(
        f"/api/cases/{case_id}/events", params={"event_type": "process_created", "limit": 500}
    ).json()["items"]
    checked = 0
    for event in created:
        detail = api.get(f"/api/events/{event['event_id']}").json()
        for link in detail["links"]["incoming"]:
            if link["link_type"] == "parent_process_of":
                parent = api.get(f"/api/events/{link['event_id']}").json()
                assert (
                    parent["extra"]["process_guid"]
                    == detail["extra"]["parent_process_guid"]
                    == link["basis"]["value"]
                )
                checked += 1
    assert checked > 10


def test_index_job_is_queued_once_per_batch(api: TestClient, run_jobs: RunJobs) -> None:
    case_id = new_case(api)
    for n in range(3):
        upload(api, case_id, AUTH, f"auth{n}.log", **HINTS)
    run_jobs()
    jobs = api.get(f"/api/cases/{case_id}/jobs").json()
    assert sum(j["job_type"] == "index_case" for j in jobs) == 1
    response = api.post(f"/api/cases/{case_id}/index")
    assert response.status_code == 202
    assert run_jobs() == 1


@pytest.mark.parametrize(
    "path",
    ["/api/cases/CASE-x/timeline", "/api/cases/CASE-x/entities", "/api/cases/CASE-x/sessions"],
)
def test_unknown_case(api: TestClient, path: str) -> None:
    assert api.get(path).status_code == 404
