"""Property tests: parsers survive arbitrary input and never lose records."""

import contextlib
import hashlib
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mizar.parsers import REGISTRY
from mizar.parsers.base import FileParseError

from .parser_harness import run

TEXT_FORMATS = sorted(f for f in REGISTRY if f != "windows_evtx")
LINE_FORMATS = (
    "linux_syslog",
    "syslog_rfc5424",
    "journald_json",
    "web_access",
    "zeek_json",
    "cef",
    "leef",
    "squid",
    "generic_text",
    "generic_jsonl",
)

# Mix of log-like fragments and arbitrary bytes, so parsers get past their first checks.
FRAGMENTS = st.sampled_from(
    [
        b"Oct 29 12:00:01 h sshd[1]: ",
        b"Failed password for ",
        b"<34>1 2026-10-29T12:00:01Z ",
        b'{"ts": 1, "uid": "x"}',
        b"CEF:0|a|b|",
        b"LEEF:2.0|",
        b"type=SYSCALL msg=audit(1.0:1): ",
        b"#fields\tts\tuid\n",
        b"<Event>",
        b"</Event>",
        b'"',
        b"\\",
        b"\n",
        b"\r\n",
        b"\x00",
        b"\xff",
        b"[",
        b"]",
        b"=",
        b"|",
        b"\t",
    ]
)
PAYLOAD = st.lists(st.one_of(FRAGMENTS, st.binary(max_size=40)), max_size=40).map(b"".join)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(data=PAYLOAD, format_id=st.sampled_from(TEXT_FORMATS))
def test_parsers_never_crash(data: bytes, format_id: str) -> None:
    # run() also validates every event against the JSON Schema. A declared, reported
    # file-level failure (FileParseError) is acceptable; anything else is a bug.
    with tempfile.TemporaryDirectory() as tmp, contextlib.suppress(FileParseError):
        run(format_id, data, Path(tmp), encoding="utf-8")


@pytest.mark.parametrize("format_id", LINE_FORMATS)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(data=PAYLOAD)
def test_line_parsers_keep_every_line(format_id: str, data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        events, _, raws = run(format_id, data, Path(tmp), encoding="utf-8")
    lines = [line.rstrip(b"\r") for line in data.split(b"\n") if line.rstrip(b"\r").strip()]
    assert len(events) == len(lines)
    assert raws == [None] * len(events)  # line records are read back from the evidence file
    for event, line in zip(events, lines, strict=True):
        locator = event["original_record_reference"]
        span = data[locator["byte_offset"] : locator["byte_offset"] + locator["byte_length"]]
        assert span == line
        assert hashlib.sha256(span).hexdigest() == event["record_hash"]
