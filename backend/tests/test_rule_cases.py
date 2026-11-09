"""Per-rule positive and negative cases through parsing and a real analysis run."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from .analysis_helpers import RunJobs, analyze, by_rule, new_case, upload

T0 = datetime(2026, 10, 27, 8, 0, tzinfo=UTC)
HINTS = {"timezone_hint": "UTC", "year_hint": 2026}
Files = list[tuple[str, bytes, dict[str, Any]]]


def bsd(ts: datetime) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


def syslog(*lines: tuple[datetime, str]) -> bytes:
    return "".join(f"{bsd(ts)} srv01 {text}\n" for ts, text in lines).encode()


def windows(generator: Any, *items: tuple[int, datetime, dict[str, str]], **kw: str) -> bytes:
    body = "".join(
        generator._win_event(eid, ts, 100 + n, "WS01", data, **kw)
        for n, (eid, ts, data) in enumerate(items)
    )
    return f"<Events>{body}</Events>".encode()


def failures(
    count: int, start: datetime = T0, ip: str = "203.0.113.7"
) -> list[tuple[datetime, str]]:
    return [
        (
            start + timedelta(seconds=i),
            f"sshd[{900 + i}]: Failed password for root from {ip} port {40000 + i} ssh2",
        )
        for i in range(count)
    ]


def run_case(
    api: TestClient, run_jobs: RunJobs, files: Files, overrides: dict[str, Any] | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    case_id = new_case(api)
    for name, data, hints in files:
        upload(api, case_id, data, name, **hints)
    return analyze(api, run_jobs, case_id, overrides)


CASES: list[tuple[str, str, Callable[[Any], Files], int]] = [
    (
        "AUTH-001",
        "20 failures within 10 minutes",
        lambda g: [("auth.log", syslog(*failures(20)), HINTS)],
        1,
    ),
    (
        "AUTH-001",
        "19 failures stay below the threshold",
        lambda g: [("auth.log", syslog(*failures(19)), HINTS)],
        0,
    ),
    (
        "AUTH-001",
        "failures spread over hours",
        lambda g: [
            (
                "auth.log",
                syslog(
                    *[(T0 + timedelta(minutes=31 * i), t) for i, (_, t) in enumerate(failures(25))]
                ),
                HINTS,
            )
        ],
        0,
    ),
    (
        "AUTH-001",
        "without a year hint the window cannot be evaluated",
        lambda g: [("auth.log", syslog(*failures(30)), {"timezone_hint": "UTC"})],
        0,
    ),
    (
        "AUTH-005",
        "account lockout",
        lambda g: [
            (
                "sec.xml",
                windows(g, (4740, T0, {"TargetUserName": "jdoe", "TargetDomainName": "WS01"})),
                {},
            )
        ],
        1,
    ),
    (
        "AUTH-007",
        "new source after the baseline",
        lambda g: [
            (
                "auth.log",
                syslog(
                    (T0, "sshd[1]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2"),
                    (
                        T0 + timedelta(hours=30),
                        "sshd[2]: Accepted publickey for alice from 10.0.0.5 port 2 ssh2",
                    ),
                    (
                        T0 + timedelta(hours=31),
                        "sshd[3]: Accepted publickey for alice from 198.51.100.9 port 3 ssh2",
                    ),
                ),
                HINTS,
            )
        ],
        1,
    ),
    (
        "AUTH-007",
        "several new sources for one user give one finding",
        lambda g: [
            (
                "auth.log",
                syslog(
                    (T0, "sshd[1]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2"),
                    (T0, "sshd[1]: Accepted publickey for bob from 10.0.0.6 port 1 ssh2"),
                    (
                        T0 + timedelta(hours=30),
                        "sshd[3]: Accepted publickey for alice from 198.51.100.9 port 3 ssh2",
                    ),
                    (
                        T0 + timedelta(hours=31),
                        "sshd[4]: Accepted publickey for alice from 198.51.100.10 port 4 ssh2",
                    ),
                    (
                        T0 + timedelta(hours=32),
                        "sshd[5]: Accepted publickey for alice from 198.51.100.9 port 5 ssh2",
                    ),
                ),
                HINTS,
            )
        ],
        1,
    ),
    (
        "AUTH-007",
        "everything inside the baseline",
        lambda g: [
            (
                "auth.log",
                syslog(
                    (T0, "sshd[1]: Accepted publickey for alice from 10.0.0.5 port 1 ssh2"),
                    (
                        T0 + timedelta(hours=3),
                        "sshd[3]: Accepted publickey for alice from 198.51.100.9 port 3 ssh2",
                    ),
                ),
                HINTS,
            )
        ],
        0,
    ),
    (
        "AUTH-009",
        "explicit credentials to another server",
        lambda g: [
            (
                "sec.xml",
                windows(
                    g,
                    (
                        4648,
                        T0,
                        {
                            "SubjectUserName": "jdoe",
                            "TargetUserName": "admin",
                            "TargetServerName": "FS01",
                            "IpAddress": "-",
                        },
                    ),
                ),
                {},
            )
        ],
        1,
    ),
    (
        "AUTH-009",
        "explicit credentials to localhost",
        lambda g: [
            (
                "sec.xml",
                windows(
                    g,
                    (
                        4648,
                        T0,
                        {
                            "SubjectUserName": "jdoe",
                            "TargetUserName": "admin",
                            "TargetServerName": "localhost",
                        },
                    ),
                ),
                {},
            )
        ],
        0,
    ),
    (
        "PRIV-001",
        "sudo refused",
        lambda g: [
            (
                "auth.log",
                syslog(
                    (
                        T0,
                        "sudo:   mallory : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
                    )
                ),
                HINTS,
            )
        ],
        1,
    ),
    (
        "PRIV-001",
        "ordinary sudo use",
        lambda g: [
            (
                "auth.log",
                syslog((T0, "sudo:   alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls")),
                HINTS,
            )
        ],
        0,
    ),
    (
        "PRIV-002",
        "three sudo password failures",
        lambda g: [
            (
                "auth.log",
                syslog(
                    *[
                        (
                            T0 + timedelta(seconds=10 * i),
                            "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
                        )
                        for i in range(3)
                    ]
                ),
                HINTS,
            )
        ],
        1,
    ),
    (
        "PRIV-002",
        "two failures",
        lambda g: [
            (
                "auth.log",
                syslog(
                    *[
                        (
                            T0 + timedelta(seconds=10 * i),
                            "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
                        )
                        for i in range(2)
                    ]
                ),
                HINTS,
            )
        ],
        0,
    ),
    (
        "PRIV-004",
        "admin first seen after baseline, machine account ignored",
        lambda g: [
            (
                "sec.xml",
                windows(
                    g,
                    (4672, T0, {"SubjectUserName": "jdoe", "SubjectLogonId": "0x1"}),
                    (
                        4672,
                        T0 + timedelta(hours=30),
                        {"SubjectUserName": "eve", "SubjectLogonId": "0x2"},
                    ),
                    (
                        4672,
                        T0 + timedelta(hours=31),
                        {"SubjectUserName": "WS01$", "SubjectLogonId": "0x3"},
                    ),
                ),
                {},
            )
        ],
        1,
    ),
    (
        "PRIV-005",
        "shadow read by cat",
        lambda g: [
            (
                "audit.log",
                (
                    b'type=SYSCALL msg=audit(1761552000.000:10): syscall=257 success=yes pid=4 auid=1000 ses=2 comm="cat" exe="/usr/bin/cat" key="creds"\n'
                    b'type=PATH msg=audit(1761552000.000:10): item=0 name="/etc/shadow"\n'
                    b"type=EOE msg=audit(1761552000.000:10):\n"
                ),
                {},
            )
        ],
        1,
    ),
    (
        "PRIV-005",
        "unrelated file",
        lambda g: [
            (
                "audit.log",
                (
                    b'type=SYSCALL msg=audit(1761552000.000:10): syscall=257 success=yes pid=4 auid=1000 ses=2 comm="cat" exe="/usr/bin/cat" key="x"\n'
                    b'type=PATH msg=audit(1761552000.000:10): item=0 name="/etc/hosts"\n'
                ),
                {},
            )
        ],
        0,
    ),
    (
        "PERS-005",
        "authorized_keys written",
        lambda g: [
            (
                "audit.log",
                (
                    b'type=SYSCALL msg=audit(1761552000.000:11): syscall=257 success=yes pid=5 auid=0 ses=3 comm="bash" exe="/usr/bin/bash" key="ssh"\n'
                    b'type=PATH msg=audit(1761552000.000:11): item=0 name="/root/.ssh/authorized_keys"\n'
                ),
                {},
            )
        ],
        1,
    ),
    (
        "NET-003",
        "Zeek notice",
        lambda g: [
            (
                "notice.log",
                b'{"ts":1761552000.0,"uid":"C1","id.orig_h":"10.0.0.9","note":"Scan::Port_Scan","msg":"10.0.0.9 scanned 30 ports"}\n',
                {},
            )
        ],
        1,
    ),
    (
        "DEF-001",
        "Security log cleared",
        lambda g: [
            ("sec.xml", windows(g, (1102, T0, {}), provider="Microsoft-Windows-Eventlog"), {})
        ],
        1,
    ),
]


@pytest.mark.parametrize(
    ("rule_id", "case", "files", "expected"), CASES, ids=[f"{c[0]}:{c[1]}" for c in CASES]
)
def test_rule_case(
    rule_id: str,
    case: str,
    files: Callable[[Any], Files],
    expected: int,
    api: TestClient,
    run_jobs: RunJobs,
    generator: Any,
) -> None:
    run, findings = run_case(api, run_jobs, files(generator))
    assert run["status"] == "succeeded", run
    assert len(by_rule(findings, rule_id)) == expected, [f["title"] for f in findings]


def test_override_changes_threshold_and_is_recorded(api: TestClient, run_jobs: RunJobs) -> None:
    files = [("auth.log", syslog(*failures(6)), HINTS)]
    _, default = run_case(api, run_jobs, files)
    run, tuned = run_case(api, run_jobs, files, {"AUTH-001": {"min_failures": 5}})
    assert by_rule(default, "AUTH-001") == []
    (finding,) = by_rule(tuned, "AUTH-001")
    assert finding["entities"]["source_ip"] == "203.0.113.7"
    detail = api.get(f"/api/runs/{run['run_id']}").json()
    assert detail["manifest"]["params"]["AUTH-001"] == {"min_failures": 5, "window": "10m"}
    assert detail["overrides"] == {"AUTH-001": {"min_failures": 5}}


def test_same_log_collected_twice_is_counted_once(api: TestClient, run_jobs: RunJobs) -> None:
    data = syslog(*failures(15))
    _, findings = run_case(
        api, run_jobs, [("auth.log", data, HINTS), ("auth.log.copy", data, HINTS)]
    )
    # 30 records, but only 15 distinct attempts: below the threshold of 20.
    assert by_rule(findings, "AUTH-001") == []
    _, tuned = run_case(
        api,
        run_jobs,
        [("a.log", data, HINTS), ("b.log", data, HINTS)],
        {"AUTH-001": {"min_failures": 15}},
    )
    (finding,) = by_rule(tuned, "AUTH-001")
    assert finding["event_count"] == 15


def test_rsyslog_repeat_counts_toward_threshold(api: TestClient, run_jobs: RunJobs) -> None:
    lines = [
        *failures(1),
        (
            T0 + timedelta(seconds=5),
            "sshd[900]: message repeated 19 times: [ Failed password for root from 203.0.113.7 port 40000 ssh2]",
        ),
    ]
    _, findings = run_case(api, run_jobs, [("auth.log", syslog(*lines), HINTS)])
    (finding,) = by_rule(findings, "AUTH-001")
    detail = api.get(f"/api/findings/{finding['finding_id']}").json()
    assert detail["observed_evidence"]["weighted_count"] == 20
    assert detail["event_count"] == 2  # two records stand for twenty attempts
    assert "20 failed SSH" in finding["description"]


def test_privileged_group_rule_ignores_ordinary_groups(api: TestClient, run_jobs: RunJobs) -> None:
    _, findings = run_case(
        api,
        run_jobs,
        [
            (
                "auth.log",
                syslog(
                    (T0, "usermod[1]: add 'eve' to group 'audio'"),
                    (T0, "usermod[2]: add 'eve' to group 'wheel'"),
                ),
                HINTS,
            )
        ],
    )
    (finding,) = by_rule(findings, "PRIV-003")
    assert finding["entities"]["group"] == "wheel"
