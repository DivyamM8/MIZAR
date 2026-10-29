import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from evtx import PyEvtxParser

from mizar.parsers import REGISTRY
from mizar.parsers.base import FileParseError
from mizar.parsers.syslog import LinuxSyslogParser

from .parser_harness import run

EVTX_SAMPLES = Path(__file__).resolve().parents[2] / "fixtures" / "third_party" / "evtx"
CORE = (
    "timestamp_utc",
    "hostname",
    "username",
    "user_domain",
    "source_ip",
    "source_port",
    "event_type",
    "event_outcome",
    "event_code",
    "session_id",
    "process_name",
)


def one(format_id: str, line: str, tmp_path: Path, **kwargs: Any) -> dict[str, Any]:
    events, problems, _ = run(format_id, (line + "\n").encode(), tmp_path, **kwargs)
    assert len(events) == 1 and not problems
    return events[0]


# --- Linux -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "sshd[12]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2",
            {
                "event_type": "logon_failed",
                "username": "admin",
                "source_ip": "203.0.113.5",
                "source_port": 52144,
                "event_outcome": "failure",
                "session_id": "sshd[12]",
            },
        ),
        (
            "sshd[12]: Accepted publickey for root from 2001:db8::5 port 22 ssh2: RSA SHA256:x",
            {
                "event_type": "logon",
                "username": "root",
                "source_ip": "2001:db8::5",
                "event_outcome": "success",
            },
        ),
        (
            "sshd[12]: Invalid user test from 198.51.100.1 port 4444",
            {"event_type": "invalid_user", "username": "test", "source_ip": "198.51.100.1"},
        ),
        (
            "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
            {"event_type": "sudo_command", "username": "alice", "event_outcome": "success"},
        ),
        (
            "sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/bin/sh",
            {"event_type": "sudo_not_in_sudoers", "username": "bob", "event_outcome": "failure"},
        ),
        (
            "useradd[9]: new user: name=eve, UID=1002, GID=1002, home=/home/eve, shell=/bin/bash",
            {
                "event_type": "user_created",
                "username": "eve",
                "event_category": "account_management",
            },
        ),
        (
            "usermod[9]: add 'eve' to group 'sudo'",
            {"event_type": "group_member_added", "username": "eve"},
        ),
        (
            "su[4]: FAILED SU (to root) mallory on pts/2",
            {"event_type": "su_failed", "username": "mallory", "event_outcome": "failure"},
        ),
        (
            "crontab[7]: (root) REPLACE (root)",
            {"event_type": "crontab_replaced", "username": "root"},
        ),
        (
            "kernel: [ 12.3] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.1 PROTO=TCP "
            "SPT=40000 DPT=23",
            {
                "event_type": "connection_denied",
                "source_ip": "198.51.100.7",
                "destination_port": 23,
                "protocol": "tcp",
                "source_type": "firewall",
            },
        ),
        (
            "sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.5  user=root",
            {"event_type": "pam_auth_failure", "username": "root", "source_ip": "203.0.113.5"},
        ),
        (
            "systemd[1]: Started Session 4 of user alice.",
            {"event_type": "syslog_message", "username": None, "process_name": "systemd"},
        ),
    ],
)
def test_syslog_messages(message: str, expected: dict[str, Any], tmp_path: Path) -> None:
    event = one(
        "linux_syslog",
        f"Oct 29 12:00:01 web01 {message}",
        tmp_path,
        year_hint=2026,
        timezone_hint="UTC",
    )
    for key, value in expected.items():
        assert event[key] == value, key
    assert event["hostname"] == "web01"
    assert event["parsing_status"] == "parsed"


def test_syslog_without_year_has_no_utc_but_keeps_original(tmp_path: Path) -> None:
    event = one(
        "linux_syslog",
        "Oct 29 12:00:01 web01 CRON[5]: (root) CMD (true)",
        tmp_path,
        timezone_hint="UTC",
    )
    assert event["timestamp_original"] == "Oct 29 12:00:01"
    assert event["timestamp_utc"] is None
    assert event["timezone_assumption"] == "none"
    assert "year_unknown" in event["parse_warnings"]


def test_syslog_year_rollover_is_flagged(tmp_path: Path) -> None:
    data = b"Dec 31 23:59:59 h a: one\nJan  1 00:00:01 h a: two\nJan  1 00:00:02 h a: three\n"
    events, _, _ = run("linux_syslog", data, tmp_path, year_hint=2025, timezone_hint="UTC")
    assert [e["timestamp_utc"].year for e in events] == [2025, 2026, 2026]
    assert ["year_rollover_inferred" in e["parse_warnings"] for e in events] == [False, True, True]


def test_repeated_message_keeps_count(tmp_path: Path) -> None:
    event = one(
        "linux_syslog",
        "Oct 29 12:00:01 h sshd[7]: message repeated 5 times: "
        "[ Failed password for root from 203.0.113.5 port 22 ssh2]",
        tmp_path,
    )
    assert event["event_type"] == "logon_failed"
    assert event["extra"]["repeat_count"] == 5


def test_invalid_ip_is_nulled_not_coerced(tmp_path: Path) -> None:
    event = one(
        "linux_syslog",
        "Oct 29 12:00:01 h sshd[7]: Failed password for root from 999.1.1.1 port 99999 ssh2",
        tmp_path,
    )
    assert event["source_ip"] is None and event["source_port"] is None
    assert event["extra"]["source_ip_raw"] == "999.1.1.1"
    assert event["extra"]["source_port_raw"] == "99999"
    assert {"invalid_ip", "invalid_port"} <= set(event["parse_warnings"])
    assert event["parsing_status"] == "partial"


def test_unrecognized_line_is_kept_unparsed(tmp_path: Path) -> None:
    event = one("linux_syslog", "this is not a syslog line", tmp_path)
    assert event["parsing_status"] == "unparsed"
    assert event["message"] == "this is not a syslog line"


def test_overlong_line_is_capped_but_hashed_in_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mizar.parsers import textio

    monkeypatch.setattr(textio, "MAX_LINE_BYTES", 64)
    line = b"Oct 29 12:00:01 h app: " + b"A" * 500
    events, _, raws = run("linux_syslog", line + b"\nOct 29 12:00:02 h app: next\n", tmp_path)
    assert events[0]["record_hash"] == hashlib.sha256(line).hexdigest()
    assert events[0]["original_record_reference"]["byte_length"] == len(line)
    assert raws[0] is None  # read back from the evidence file, not copied
    assert "truncated_record" in events[0]["parse_warnings"]
    assert events[1]["original_record_reference"]["byte_offset"] == len(line) + 1


def test_parser_exception_isolated_to_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = LinuxSyslogParser.normalize

    def flaky(self: LinuxSyslogParser, unit: Any) -> Any:
        if b"boom" in unit.raw:
            raise KeyError("bug")
        return original(self, unit)

    monkeypatch.setattr(LinuxSyslogParser, "normalize", flaky)
    data = b"Oct 29 12:00:01 h a: ok\nOct 29 12:00:02 h a: boom\nOct 29 12:00:03 h a: ok\n"
    events, _, _ = run("linux_syslog", data, tmp_path)
    assert [e["parsing_status"] for e in events] == ["parsed", "unparsed", "parsed"]
    assert events[1]["parse_warnings"] == ["parser_exception"]
    assert events[1]["message"] == "Oct 29 12:00:02 h a: boom"


def test_event_ids_are_stable_across_parses(tmp_path: Path) -> None:
    data = b"Oct 29 12:00:01 h a: one\nOct 29 12:00:01 h a: one\n"
    first, _, _ = run("linux_syslog", data, tmp_path)
    second, _, _ = run("linux_syslog", data, tmp_path)
    assert [e["event_id"] for e in first] == [e["event_id"] for e in second]
    assert first[0]["event_id"] != first[1]["event_id"]  # identical lines are distinct records


def test_rfc5424_structured_data(tmp_path: Path) -> None:
    event = one(
        "syslog_rfc5424",
        '<165>1 2026-10-29T12:00:02+05:30 web01 app 77 ID47 [ex@1 a="1\\"x"][y@2 c="3"] '
        "\ufeffstarted",
        tmp_path,
    )
    assert event["extra"]["structured_data"] == [
        {"id": "ex@1", "params": {"a": '1"x'}},
        {"id": "y@2", "params": {"c": "3"}},
    ]
    assert event["message"] == "started"
    assert event["process_id"] == 77
    assert event["timezone_assumption"] == "explicit"


def test_journald(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1761739201123456",
            "_HOSTNAME": "web01",
            "SYSLOG_IDENTIFIER": "sshd",
            "_PID": "9",
            "MESSAGE": "Invalid user test from 203.0.113.9 port 4444",
        }
    )
    event = one("journald_json", line, tmp_path)
    assert (event["event_type"], event["source_ip"], event["timezone_assumption"]) == (
        "invalid_user",
        "203.0.113.9",
        "format_defined_utc",
    )
    assert event["original_record_reference"]["kind"] == "json_line"


def test_auditd_groups_records_by_serial(tmp_path: Path) -> None:
    data = (
        b"type=SYSCALL msg=audit(1761739202.000:457): syscall=257 success=yes pid=200 auid=1000 "
        b'comm="cat" exe="/usr/bin/cat" ses=3 key="shadow"\x1dAUID="alice" UID="root"\n'
        b"type=USER_LOGIN msg=audit(1761739203.000:458): pid=1 ses=4294967295 msg='op=login "
        b'acct="root" exe="/usr/sbin/sshd" addr=203.0.113.5 terminal=ssh res=failed\'\n'
        b'type=PATH msg=audit(1761739202.000:457): item=0 name="/etc/shadow"\n'
        b"type=PROCTITLE msg=audit(1761739202.000:457): proctitle=636174002F6574632F736861646F77\n"
        b"type=EOE msg=audit(1761739202.000:457):\n"
    )
    events, _, _ = run("auditd", data, tmp_path)
    watch = next(e for e in events if e["event_code"] == "SYSCALL")
    assert watch["event_type"] == "audit_watch_triggered"
    assert watch["username"] == "alice"
    assert watch["extra"]["paths"] == ["/etc/shadow"]
    assert watch["extra"]["fields"]["proctitle"] == "cat /etc/shadow"
    assert watch["original_record_reference"]["lines"] == [1, 3, 4, 5]
    login = next(e for e in events if e["event_code"] == "USER_LOGIN")
    assert (login["event_type"], login["username"], login["source_ip"]) == (
        "logon_failed",
        "root",
        "203.0.113.5",
    )
    assert login["session_id"] is None


# --- web and network -------------------------------------------------------------------


def test_web_access(tmp_path: Path) -> None:
    event = one(
        "web_access",
        '203.0.113.9 - - [29/Oct/2026:12:00:01 +0530] "GET /i.php?id=1%27%20OR%201=1 HTTP/1.1" '
        '200 512 "-" "sqlmap/1.8"',
        tmp_path,
    )
    assert event["source_ip"] == "203.0.113.9"
    assert event["event_code"] == "200"
    assert event["timestamp_utc"].hour == 6
    assert event["extra"]["url_decoded"] == "/i.php?id=1' OR 1=1"
    assert event["extra"]["user_agent"] == "sqlmap/1.8"


def test_web_access_malformed_request_kept(tmp_path: Path) -> None:
    event = one(
        "web_access",
        '10.0.0.9 - - [29/Oct/2026:12:00:03 +0000] "\\x16\\x03" 400 0 "-" "-"',
        tmp_path,
    )
    assert event["extra"]["malformed_request"] is True
    assert event["parsing_status"] == "parsed"


def test_zeek_tsv(tmp_path: Path) -> None:
    data = (
        b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        b"#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
        b"conn_state\tservice\n"
        b"1761739201.000001\tCabc\t10.0.0.5\t52144\t10.0.0.1\t22\ttcp\tREJ\t-\n"
    )
    events, _, _ = run("zeek_tsv", data, tmp_path)
    (event,) = events
    assert (event["session_id"], event["destination_port"], event["event_outcome"]) == (
        "Cabc",
        22,
        "failure",
    )
    assert event["extra"]["zeek_fields"]["service"] is None


def test_cef_and_leef(tmp_path: Path) -> None:
    cef = one(
        "cef",
        "Oct 29 12:00:01 fw01 CEF:0|Vendor|FW|1.0|sig\\|1|Blocked|5|src=203.0.113.5 dst=10.0.0.1 "
        "dpt=22 act=blocked msg=two words rt=1761739201000",
        tmp_path,
    )
    assert (cef["event_type"], cef["event_code"], cef["hostname"], cef["message"]) == (
        "connection_denied",
        "sig|1",
        "fw01",
        "two words",
    )
    assert cef["timezone_assumption"] == "format_defined_utc"
    leef = one(
        "leef",
        "LEEF:2.0|Vendor|Product|1.0|LoginFailed|^|src=203.0.113.5^usrName=bob^"
        "devTime=2026-10-29T12:00:01Z",
        tmp_path,
    )
    assert (leef["username"], leef["source_ip"], leef["timezone_assumption"]) == (
        "bob",
        "203.0.113.5",
        "explicit",
    )


def test_squid(tmp_path: Path) -> None:
    event = one(
        "squid",
        "1761739202.456     15 10.0.0.6 TCP_DENIED/403 3900 CONNECT evil.test:443 bob "
        "HIER_NONE/- text/html",
        tmp_path,
    )
    assert (event["event_type"], event["username"], event["event_outcome"]) == (
        "proxy_request_denied",
        "bob",
        "failure",
    )


def test_generic_never_assigns_ip_roles(tmp_path: Path) -> None:
    event = one(
        "generic_text",
        "2026-10-29 12:00:01 conn 203.0.113.5 -> 10.0.0.1 failed",
        tmp_path,
        timezone_hint="UTC",
    )
    assert event["source_ip"] is None and event["destination_ip"] is None
    assert event["extra"]["ips_found"] == ["203.0.113.5", "10.0.0.1"]
    assert event["parsing_status"] == "partial"


# --- Windows ---------------------------------------------------------------------------


def test_evtx_native_mapping(tmp_path: Path) -> None:
    events, problems, _ = run("windows_evtx", EVTX_SAMPLES / "new-user-security.evtx", tmp_path)
    assert not problems
    created = next(e for e in events if e["event_code"] == "4720")
    assert (created["event_type"], created["username"], created["hostname"]) == (
        "user_created",
        "IEUser",
        "IE8Win7",
    )
    assert created["timezone_assumption"] == "format_defined_utc"
    assert created["extra"]["event_data"]["TargetUserName"] == "IEUser"
    added = [e for e in events if e["event_type"] == "group_member_added"]
    assert len(added) == 3
    assert all(e["username"].startswith("S-1-5-21-") for e in added)  # member known by SID only


def test_evtx_failed_logon(tmp_path: Path) -> None:
    events, _, _ = run("windows_evtx", EVTX_SAMPLES / "Security_short_selected.evtx", tmp_path)
    failed = next(e for e in events if e["event_code"] == "4625")
    assert (failed["username"], failed["source_ip"], failed["source_port"]) == (
        "Administrator",
        "23.94.153.202",
        60167,
    )
    assert failed["extra"]["logon_type"] == 10


def test_evtx_damaged_chunks_are_reported(tmp_path: Path) -> None:
    events, problems, _ = run(
        "windows_evtx", EVTX_SAMPLES / "sample_with_a_bad_chunk_magic.evtx", tmp_path
    )
    assert len(events) == 270
    assert [p.code for p in problems] == ["EVTX_CHUNK_UNREADABLE"] * 2
    locators = [json.dumps(e["original_record_reference"], sort_keys=True) for e in events]
    assert len(set(locators)) == len(locators)


def test_evtx_sysmon(tmp_path: Path) -> None:
    events, _, _ = run("windows_evtx", EVTX_SAMPLES / "sysmon.evtx", tmp_path)
    counts = Counter(e["event_type"] for e in events)
    assert counts["process_created"] == 227
    network = next(e for e in events if e["event_type"] == "network_connection")
    assert (network["username"], network["user_domain"]) == ("SYSTEM", "NT AUTHORITY")
    assert network["destination_port"] == 443


def test_evtx_corrupt_header_fails_file(tmp_path: Path) -> None:
    with pytest.raises(FileParseError) as info:
        run("windows_evtx", b"ElfFile\x00" + b"\xff" * 4096, tmp_path)
    assert info.value.code == "EVTX_CORRUPT_HEADER"


def test_xml_and_json_exports_match_native(tmp_path: Path) -> None:
    source = EVTX_SAMPLES / "Security_short_selected.evtx"
    native, _, _ = run("windows_evtx", source, tmp_path)
    xml = "".join(r["data"].split("?>", 1)[-1] for r in PyEvtxParser(str(source)).records())
    exported, _, _ = run("windows_evtx_xml", f"<Events>{xml}</Events>".encode("utf-16"), tmp_path)
    lines = "\n".join(
        json.dumps(json.loads(r["data"])) for r in PyEvtxParser(str(source)).records_json()
    )
    jsonl, _, _ = run("windows_evtx_json", lines.encode(), tmp_path)
    for other in (exported, jsonl):
        assert [{k: e[k] for k in CORE} for e in other] == [{k: e[k] for k in CORE} for e in native]


def test_xml_with_doctype_is_refused(tmp_path: Path) -> None:
    payload = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<!DOCTYPE x [<!ENTITY a "aaaa">]><System><EventID>1</EventID></System></Event>'
    )
    events, _, _ = run("windows_evtx_xml", payload.encode(), tmp_path)
    assert events[0]["parsing_status"] == "unparsed"
    assert events[0]["parse_warnings"] == ["xml_doctype_refused"]


def test_get_winevent_positional_data_is_not_guessed(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "Id": 4625,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "MachineName": "WS01",
                "TimeCreated": "/Date(1761739201000)/",
                "Properties": [{"Value": "S-1-0-0"}, {"Value": "Administrator"}],
            }
        ],
        indent=2,
    )
    events, _, _ = run("windows_evtx_json", payload.encode(), tmp_path)
    (event,) = events
    assert event["event_type"] == "logon_failed"
    assert event["username"] is None
    assert event["extra"]["event_data_values"] == ["S-1-0-0", "Administrator"]
    assert event["parsing_status"] == "partial"
    assert "event_data_positional" in event["parse_warnings"]


def test_event_viewer_csv(tmp_path: Path) -> None:
    data = (
        "Level,Date and Time,Source,Event ID,Task Category\r\n"
        "Information,10/29/2026 12:00:01 PM,Microsoft-Windows-Security-Auditing,4624,Logon,"
        '"An account was successfully logged on.\r\n\r\nSubject: x"\r\n'
        "Error,29.10.2026 12:00:01,Service Control Manager,7045,None,x\r\n"
    ).encode("utf-8-sig")
    events, _, _ = run("windows_evtx_csv", data, tmp_path, timezone_hint="America/New_York")
    first, second = events
    assert first["timestamp_utc"].hour == 16
    assert first["message"].startswith("An account was successfully logged on.")
    assert first["original_record_reference"] == {"kind": "csv_row", "row": 1, "line": 2}
    assert second["timestamp_utc"] is None  # unknown locale layout is not guessed
    assert second["original_record_reference"]["line"] == 5


def test_every_registered_parser_has_a_version() -> None:
    for parser in REGISTRY.values():
        assert parser.version.count(".") == 2
