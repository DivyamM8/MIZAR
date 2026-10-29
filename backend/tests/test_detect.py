import json

import pytest

from mizar.ingest.detect import HEAD_BYTES, decode_head, detect_format
from mizar.ingest.formats import FORMATS

SAMPLES: dict[str, str] = {
    "linux_syslog": (
        "Oct 29 12:00:01 web01 sshd[1234]: Failed password for root from 203.0.113.5 "
        "port 52144 ssh2\n"
        "Oct 29 12:00:02 web01 sshd[1234]: Connection closed by 203.0.113.5 port 52144\n"
        "Oct  9 08:15:00 web01 CRON[99]: (root) CMD (run-parts /etc/cron.hourly)\n"
    ),
    "syslog_rfc5424": (
        "<34>1 2026-10-29T12:00:01.003Z web01 sshd 1234 - - Failed password for root\n"
        '<165>1 2026-10-29T12:00:02+05:30 web01 app - ID47 [ex@32473 a="1"] started\n'
    ),
    "auditd": (
        "type=USER_AUTH msg=audit(1761739201.123:456): pid=1 uid=0 auid=4294967295 "
        'ses=4294967295 msg=\'op=PAM:authentication acct="root" exe="/usr/sbin/sshd"\'\n'
        "type=SYSCALL msg=audit(1761739202.000:457): arch=c000003e syscall=59 success=yes\n"
    ),
    "web_access": (
        '203.0.113.9 - - [29/Oct/2026:12:00:01 +0000] "GET /index.php?id=1%27 HTTP/1.1" '
        '200 512 "-" "sqlmap/1.8"\n'
        '2001:db8::1 - alice [29/Oct/2026:12:00:02 +0530] "POST /login HTTP/1.1" 302 0 '
        '"https://example.test/" "Mozilla/5.0"\n'
    ),
    "squid": (
        "1761739201.123    120 10.0.0.5 TCP_MISS/200 1024 GET http://example.test/ - "
        "HIER_DIRECT/93.184.216.34 text/html\n"
        "1761739202.456     15 10.0.0.6 TCP_DENIED/403 3900 CONNECT evil.test:443 - "
        "HIER_NONE/- text/html\n"
    ),
    "cef": (
        "Oct 29 12:00:01 fw01 CEF:0|Vendor|Firewall|1.0|100|Blocked|5|src=203.0.113.5 "
        "dst=10.0.0.1 dpt=22\n"
        "Oct 29 12:00:02 fw01 CEF:0|Vendor|Firewall|1.0|100|Blocked|5|src=203.0.113.6 "
        "dst=10.0.0.1 dpt=23\n"
    ),
    "leef": (
        "LEEF:2.0|Vendor|Product|1.0|LoginFailed|src=203.0.113.5\tusrName=bob\n"
        "LEEF:2.0|Vendor|Product|1.0|LoginFailed|src=203.0.113.6\tusrName=amy\n"
    ),
    "journald_json": "\n".join(
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": "1761739201123456",
                "_HOSTNAME": "web01",
                "SYSLOG_IDENTIFIER": "sshd",
                "MESSAGE": f"Failed password for root from 203.0.113.{i} port 22 ssh2",
            }
        )
        for i in range(5)
    )
    + "\n",
    "zeek_json": "\n".join(
        json.dumps({"ts": 1761739201.1 + i, "uid": f"C{i}abc", "id.orig_h": "10.0.0.5"})
        for i in range(5)
    )
    + "\n",
    "zeek_tsv": (
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        "#path\tconn\n#open\t2026-10-29-12-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
        "1761739201.000000\tCabc\t10.0.0.5\t52144\t10.0.0.1\t22\ttcp\n"
    ),
    "windows_evtx_xml": (
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>"
        "</System></Event></Events>\n"
    ),
    "windows_evtx_csv": (
        "Level,Date and Time,Source,Event ID,Task Category\n"
        'Information,10/29/2026 12:00:01 PM,Microsoft-Windows-Security-Auditing,4624,Logon,"An '
        'account was successfully logged on."\n'
    ),
    "windows_evtx_json": json.dumps(
        [
            {
                "Id": 4625,
                "ProviderName": "Microsoft-Windows-Security-Auditing",
                "TimeCreated": "/Date(1761739201000)/",
                "Message": "An account failed to log on.",
            }
        ],
        indent=2,
    ),
}


@pytest.mark.parametrize("format_id", sorted(SAMPLES))
def test_each_format_is_detected(format_id: str) -> None:
    result = detect_format(SAMPLES[format_id].encode(), "sample")
    assert result.format_id == format_id, result.candidates
    assert result.confidence is not None and result.confidence >= 0.5
    assert result.candidates[0].reason


def test_every_detected_format_is_registered() -> None:
    for format_id in SAMPLES:
        assert format_id in FORMATS


def test_evtx_signature() -> None:
    result = detect_format(b"ElfFile\x00" + b"\x00" * 100, "Security.evtx")
    assert (result.format_id, result.confidence) == ("windows_evtx", 1.0)


def test_extension_is_not_trusted() -> None:
    result = detect_format(SAMPLES["web_access"].encode(), "Security.evtx")
    assert result.format_id == "web_access"


def test_evtx_named_binary_without_signature_is_flagged() -> None:
    result = detect_format(b"\x00\x01\x02\x03" * 100, "Security.evtx")
    assert result.format_id is None
    assert result.corrupt_evtx_suspected


def test_unknown_text_falls_back_to_generic() -> None:
    result = detect_format(b"hello world\nthis is not a log format\nat all\n", "notes.txt")
    assert result.format_id == "generic_text"
    assert result.confidence is None
    assert result.is_generic


def test_unknown_json_lines_fall_back_to_generic_jsonl() -> None:
    lines = "\n".join(json.dumps({"level": "info", "msg": f"m{i}"}) for i in range(10))
    assert detect_format(lines.encode(), "app.json").format_id == "generic_jsonl"


def test_utf16_exports_are_decoded() -> None:
    data = SAMPLES["windows_evtx_csv"].encode("utf-16")
    result = detect_format(data, "export.csv")
    assert result.format_id == "windows_evtx_csv"
    assert result.encoding in ("utf-16-le", "utf-16-be")


def test_utf8_bom_is_stripped() -> None:
    result = detect_format(b"\xef\xbb\xbf" + SAMPLES["windows_evtx_csv"].encode(), "x.csv")
    assert result.format_id == "windows_evtx_csv"
    assert result.encoding == "utf-8-sig"


def test_mostly_matching_file_still_detected_with_lower_score() -> None:
    lines = SAMPLES["linux_syslog"].splitlines()
    noisy = "\n".join([*lines, *lines, "garbage line"]) + "\n"
    result = detect_format(noisy.encode(), "messages")
    assert result.format_id == "linux_syslog"
    assert result.confidence is not None and result.confidence < 0.9


def test_cut_off_last_line_is_ignored_in_full_window() -> None:
    line = SAMPLES["linux_syslog"].splitlines()[0] + "\n"
    head = (line * (HEAD_BYTES // len(line) + 1)).encode()[:HEAD_BYTES]
    assert detect_format(head, "auth.log").confidence == 0.9


def test_binary_detection() -> None:
    assert decode_head(b"\x00\x01binary\x00\xff") == (None, None)
