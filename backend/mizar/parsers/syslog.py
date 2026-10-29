"""Syslog file formats: traditional/rsyslog, RFC 5424, and journald JSON export."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from decimal import Decimal
from typing import Any, BinaryIO

from mizar.parsers import timeparse
from mizar.parsers.base import (
    NO_TIMESTAMP,
    FileProblem,
    Normalized,
    ParseContext,
    Parser,
    RecordUnit,
    Timestamp,
    register,
)
from mizar.parsers.linux_messages import FAMILY_VERSION, parse_program_message
from mizar.parsers.textio import Line, iter_lines

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_BSD = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) "
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d{1,6}))? (?P<host>\S+) (?P<rest>.*)$"
)
_ISO_HEADER = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?"
    r"(?:Z|[+-]\d{2}:?\d{2})) (?P<host>\S+) (?P<rest>.*)$"
)
_TAG = re.compile(r"^(?P<prog>[^\s:\[\]]{1,64})(?:\[(?P<pid>\d{1,10})\])?: ?(?P<msg>.*)$")
_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+)(?: (?P<rest>.*))?$"
)
# A backwards month jump this large is treated as a new year (e.g. Dec -> Jan).
_ROLLOVER_MONTH_GAP = 6


def _priority(pri: str | None) -> dict[str, int]:
    if pri is None:
        return {}
    value = int(pri)
    return {"syslog_facility": value >> 3, "syslog_severity": value & 7}


def program_fields(
    program: str | None, pid: str | None, message: str, hostname: str | None
) -> tuple[dict[str, Any], str | None, str | None]:
    """Fields for a program message: (fields, parser_name, source_type)."""
    fields: dict[str, Any] = {
        "hostname": hostname,
        "process_name": program,
        "process_id": pid,
        "message": message,
        "extra": {},
    }
    found = parse_program_message(program, pid, message)
    if found is None:
        fields["event_type"] = "syslog_message"
        return fields, None, None
    extra = {**fields["extra"], **found.fields.pop("extra", {})}
    fields.update(found.fields)
    fields["extra"] = extra
    if program in ("sshd", "sshd-session") and pid:
        # sshd forks one process per connection: its PID links the session's lines.
        fields["session_id"] = f"{program}[{pid}]"
    return fields, found.parser_name, found.source_type


class _LineParser(Parser):
    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        for line in iter_lines(stream, self.ctx.encoding):
            yield RecordUnit(
                raw=line.raw,
                raw_encoding=self.ctx.encoding or "utf-8",
                locator=line.locator(),
                payload=line,
                full_hash=line.full_hash,
                warnings=line.warnings(),
            )


@register
class LinuxSyslogParser(_LineParser):
    format_id = "linux_syslog"
    name = "linux.syslog"
    version = FAMILY_VERSION
    source_type = "syslog"

    def __init__(self, ctx: ParseContext) -> None:
        super().__init__(ctx)
        self._year = ctx.year_hint
        self._previous_month: int | None = None
        self._rolled_over = False

    def _bsd_timestamp(self, match: re.Match[str]) -> Timestamp:
        end = match.end("frac") if match["frac"] else match.end("s")
        original = match.string[match.start("mon") : end]
        month = _MONTHS.get(match["mon"])
        if month is None:
            return timeparse.unparsed(original)
        if self._year is None:
            return Timestamp(original, None, "s", "none", ("year_unknown",))
        if self._previous_month is not None and self._previous_month - month >= _ROLLOVER_MONTH_GAP:
            self._year += 1
            self._rolled_over = True
        self._previous_month = month
        try:
            naive = datetime(
                self._year,
                month,
                int(match["day"]),
                int(match["h"]),
                int(match["m"]),
                int(match["s"]),
                int((match["frac"] or "0").ljust(6, "0")),
            )
        except ValueError:
            return timeparse.unparsed(original)
        precision = timeparse.precision_for(len(match["frac"] or ""))
        stamp = timeparse.from_local(original, naive, precision, self.ctx.timezone_hint)
        if self._rolled_over:
            stamp = Timestamp(
                stamp.original,
                stamp.utc,
                stamp.precision,
                stamp.assumption,
                (*stamp.warnings, "year_rollover_inferred"),
            )
        return stamp

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        text = line.text
        match = _BSD.match(text)
        if match:
            stamp = self._bsd_timestamp(match)
        else:
            match = _ISO_HEADER.match(text)
            if not match:
                return Normalized(
                    {"message": text, "extra": {}},
                    NO_TIMESTAMP,
                    status="unparsed",
                    warnings=["header_unparsed"],
                )
            stamp = timeparse.parse_iso(match["ts"], self.ctx.timezone_hint)
        host, rest = match["host"], match["rest"]
        tag = _TAG.match(rest)
        if tag:
            fields, parser_name, source_type = program_fields(
                tag["prog"], tag["pid"], tag["msg"], host
            )
        else:
            fields, parser_name, source_type = program_fields(None, None, rest, host)
        fields["extra"].update(_priority(match["pri"]))
        return Normalized(fields, stamp, parser_name=parser_name, source_type=source_type)


def _parse_structured_data(text: str) -> tuple[list[dict[str, Any]] | None, str, bool]:
    """RFC 5424 STRUCTURED-DATA. Returns (elements, remaining message, ok)."""
    if text.startswith("-"):
        return None, text[2:] if text.startswith("- ") else text[1:], True
    elements: list[dict[str, Any]] = []
    position = 0
    while position < len(text) and text[position] == "[":
        end_id = position + 1
        while end_id < len(text) and text[end_id] not in " ]":
            end_id += 1
        element: dict[str, Any] = {"id": text[position + 1 : end_id], "params": {}}
        position = end_id
        while position < len(text) and text[position] == " ":
            position += 1
            eq = text.find("=", position)
            if eq == -1 or eq + 1 >= len(text) or text[eq + 1] != '"':
                return None, text, False
            name = text[position:eq]
            position = eq + 2
            value = []
            while position < len(text) and text[position] != '"':
                if text[position] == "\\" and position + 1 < len(text):
                    position += 1
                value.append(text[position])
                position += 1
            if position >= len(text):
                return None, text, False
            element["params"][name] = "".join(value)
            position += 1
        if position >= len(text) or text[position] != "]":
            return None, text, False
        position += 1
        elements.append(element)
    message = text[position:]
    if message.startswith(" "):
        message = message[1:]
    return elements, message.removeprefix("\ufeff"), True


@register
class Syslog5424Parser(_LineParser):
    format_id = "syslog_rfc5424"
    name = "linux.syslog5424"
    version = FAMILY_VERSION
    source_type = "syslog"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        match = _5424.match(line.text)
        if not match:
            return Normalized(
                {"message": line.text, "extra": {}},
                NO_TIMESTAMP,
                status="unparsed",
                warnings=["header_unparsed"],
            )
        stamp = (
            NO_TIMESTAMP
            if match["ts"] == "-"
            else timeparse.parse_iso(match["ts"], self.ctx.timezone_hint)
        )
        elements, message, ok = _parse_structured_data(match["rest"] or "-")
        app = None if match["app"] == "-" else match["app"]
        procid = match["procid"] if match["procid"].isdigit() else None
        host = None if match["host"] == "-" else match["host"]
        fields, parser_name, source_type = program_fields(app, procid, message, host)
        extra = fields["extra"]
        extra.update(_priority(match["pri"]))
        if match["msgid"] != "-":
            extra["msgid"] = match["msgid"]
        if match["procid"] != "-" and procid is None:
            extra["procid"] = match["procid"]
        if elements:
            extra["structured_data"] = elements
        warnings = [] if ok else ["field_unparsed"]
        return Normalized(
            fields, stamp, warnings=warnings, parser_name=parser_name, source_type=source_type
        )


_JOURNAL_EXTRA = (
    "_SYSTEMD_UNIT",
    "PRIORITY",
    "_UID",
    "_GID",
    "_TRANSPORT",
    "_BOOT_ID",
    "_MACHINE_ID",
    "_EXE",
    "_CMDLINE",
    "__CURSOR",
    "SYSLOG_FACILITY",
)


@register
class JournaldJsonParser(_LineParser):
    format_id = "journald_json"
    name = "linux.journald"
    version = FAMILY_VERSION
    source_type = "journald"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        for unit in super().records(stream):
            if isinstance(unit, RecordUnit):
                unit.locator["kind"] = "json_line"
            yield unit

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        try:
            entry = json.loads(line.text)
        except ValueError:
            entry = None
        if not isinstance(entry, dict):
            return Normalized(
                {"message": line.text, "extra": {}},
                NO_TIMESTAMP,
                status="unparsed",
                warnings=["json_invalid"],
            )
        warnings: list[str] = []
        message = entry.get("MESSAGE")
        if isinstance(message, list):
            # journald exports binary-safe messages as byte arrays.
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                message = None
            warnings.append("message_binary")
        elif message is not None and not isinstance(message, str):
            message = str(message)

        realtime = entry.get("__REALTIME_TIMESTAMP")
        if isinstance(realtime, str) and realtime.isdigit():
            stamp = timeparse.from_epoch(realtime, Decimal(realtime) / 1_000_000, "us")
        elif realtime is None:
            stamp = NO_TIMESTAMP
        else:
            stamp = timeparse.unparsed(str(realtime))

        program = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
        pid = entry.get("_PID") or entry.get("SYSLOG_PID")
        fields, parser_name, source_type = program_fields(
            str(program) if program else None,
            str(pid) if pid else None,
            message or "",
            entry.get("_HOSTNAME"),
        )
        if message is None:
            fields["message"] = None
        fields["extra"].update(
            {key.lstrip("_").lower(): entry[key] for key in _JOURNAL_EXTRA if key in entry}
        )
        return Normalized(
            fields, stamp, warnings=warnings, parser_name=parser_name, source_type=source_type
        )
