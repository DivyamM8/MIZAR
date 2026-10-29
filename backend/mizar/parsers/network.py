"""Web and network logs: Apache/Nginx access, Zeek, CEF, LEEF, Squid."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import unquote_plus

from mizar.parsers import timeparse
from mizar.parsers.base import (
    NO_TIMESTAMP,
    FileProblem,
    Normalized,
    Parser,
    RecordUnit,
    Timestamp,
    none_if_dash,
    register,
)
from mizar.parsers.syslog import _BSD, _ISO_HEADER, LinuxSyslogParser
from mizar.parsers.textio import Line, iter_lines

VERSION = "1.0.0"


class _Lines(Parser):
    locator_kind = "line"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        for line in iter_lines(stream, self.ctx.encoding):
            yield RecordUnit(
                line.raw,
                self.ctx.encoding or "utf-8",
                {**line.locator(), "kind": self.locator_kind},
                payload=line,
                full_hash=line.full_hash,
                warnings=line.warnings(),
            )

    @staticmethod
    def unparsed(line: Line, warning: str = "header_unparsed") -> Normalized:
        return Normalized({"message": line.text, "extra": {}}, NO_TIMESTAMP, "unparsed", [warning])


# --- Apache / Nginx access log ---------------------------------------------------------

_QUOTED = r'"(?P<{name}>(?:[^"\\]|\\.)*)"'
_ACCESS = re.compile(
    r"^(?:(?P<vhost>\S+) )?(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    + _QUOTED.format(name="request")
    + r" (?P<status>\d{3}|-) (?P<bytes>\d+|-)"
    + r"(?: "
    + _QUOTED.format(name="referer")
    + r" "
    + _QUOTED.format(name="ua")
    + r")?(?P<rest>.*)$"
)
_ACCESS_TIME = ("%d/%b/%Y:%H:%M:%S %z",)


@register
class WebAccessParser(_Lines):
    format_id = "web_access"
    name = "web.access"
    version = VERSION
    source_type = "web_access"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        match = _ACCESS.match(line.text)
        if not match:
            return self.unparsed(line)
        request = match["request"]
        parts = request.split(" ")
        extra: dict[str, Any] = {"request": request}
        warnings: list[str] = []
        if len(parts) == 3:
            method, url, http_version = parts
            extra.update(http_method=method, url=url, http_version=http_version)
            # Decoded once for readability; detection rules see both forms.
            extra["url_decoded"] = unquote_plus(url, errors="replace")
        elif request not in ("", "-"):
            extra["malformed_request"] = True
        for key in ("referer", "ua", "vhost"):
            value = none_if_dash(match[key])
            if value is not None:
                extra[{"ua": "user_agent", "referer": "referrer"}.get(key, key)] = value
        if match["rest"].strip():
            extra["trailing_fields"] = match["rest"].strip()
        status = None if match["status"] == "-" else match["status"]
        if match["bytes"] != "-":
            extra["response_bytes"] = int(match["bytes"])
        outcome = None
        if status is not None:
            outcome = "success" if status[0] in "123" else "failure"
        stamp = timeparse.parse_with_formats(match["ts"], _ACCESS_TIME, self.ctx.timezone_hint)
        fields = {
            "source_ip": match["client"],
            "username": none_if_dash(match["user"]),
            "protocol": "http",
            "event_category": "web",
            "event_type": "http_request",
            "event_outcome": outcome,
            "event_code": status,
            "message": line.text,
            "extra": extra,
        }
        return Normalized(fields, stamp, warnings=warnings)


# --- Zeek ------------------------------------------------------------------------------


def _zeek_kind(record: dict[str, Any], path: str | None) -> str:
    if path:
        return path
    if "_path" in record:
        return str(record["_path"])
    if "query" in record and "qtype_name" in record:
        return "dns"
    if "method" in record and "uri" in record:
        return "http"
    if "conn_state" in record:
        return "conn"
    if "note" in record:
        return "notice"
    if "auth_success" in record:
        return "ssh"
    if "server_name" in record or "cipher" in record:
        return "ssl"
    return "unknown"


def _zeek_path_from_filename(filename: str) -> str | None:
    stem = PurePosixPath(filename).name.split(".", 1)[0]
    return stem if stem.isidentifier() else None


_ZEEK_TYPES = {
    "conn": ("network", "network_connection"),
    "dns": ("network", "dns_query"),
    "http": ("web", "http_request"),
    "ssl": ("network", "tls_connection"),
    "ssh": ("authentication", "ssh_connection"),
    "notice": ("network", "zeek_notice"),
    "weird": ("network", "zeek_weird"),
    "files": ("file", "file_transfer"),
}
_ZEEK_EXTRA = {
    "conn": ("service", "duration", "orig_bytes", "resp_bytes", "conn_state", "history"),
    "dns": ("query", "qtype_name", "rcode_name", "answers"),
    "http": ("method", "host", "uri", "user_agent", "status_code", "referrer"),
    "ssl": ("server_name", "version", "cipher", "validation_status", "established"),
    "ssh": ("auth_success", "auth_attempts", "client", "server", "direction"),
    "notice": ("note", "msg", "sub", "src", "dst", "actions"),
}


def zeek_normalize(record: dict[str, Any], kind: str) -> Normalized:
    ts = record.get("ts")
    if ts is None:
        stamp: Timestamp = NO_TIMESTAMP
    else:
        text = str(ts)
        fraction = text.partition(".")[2]
        try:
            stamp = timeparse.from_epoch(
                text, Decimal(text), timeparse.precision_for(len(fraction))
            )
        except InvalidOperation:
            stamp = timeparse.parse_iso(text, None)  # Zeek JSON may use ISO8601 timestamps
    category, event_type = _ZEEK_TYPES.get(kind, ("network", f"zeek_{kind}"))
    extra: dict[str, Any] = {"zeek_log": kind}
    for key in _ZEEK_EXTRA.get(kind, ()):
        if record.get(key) is not None:
            extra[key] = record[key]
    extra["zeek_fields"] = record
    outcome = None
    code = None
    if kind == "conn":
        state = record.get("conn_state")
        outcome = {"SF": "success", "REJ": "failure", "S0": "failure"}.get(str(state))
        code = state
    elif kind == "ssh" and record.get("auth_success") is not None:
        outcome = "success" if record["auth_success"] in (True, "T", "true") else "failure"
    elif kind == "http":
        code = record.get("status_code")
    elif kind == "notice":
        code = record.get("note")
    fields = {
        "source_ip": record.get("id.orig_h") or record.get("src"),
        "source_port": record.get("id.orig_p"),
        "destination_ip": record.get("id.resp_h") or record.get("dst"),
        "destination_port": record.get("id.resp_p"),
        "protocol": record.get("proto"),
        "session_id": record.get("uid"),
        "event_category": category,
        "event_type": event_type,
        "event_outcome": outcome,
        "event_code": code,
        "message": record.get("msg"),
        "extra": extra,
    }
    return Normalized(fields, stamp)


@register
class ZeekTsvParser(Parser):
    format_id = "zeek_tsv"
    name = "network.zeek_tsv"
    version = VERSION
    source_type = "zeek"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        separator = "\t"
        set_separator = ","
        empty = "(empty)"
        unset = "-"
        fields: list[str] | None = None
        path: str | None = None
        for line in iter_lines(stream, self.ctx.encoding):
            text = line.text
            if text.startswith("#"):
                directive, _, value = text[1:].partition(separator if fields else "\t")
                if text.startswith("#separator "):
                    separator = text.split(" ", 1)[1].encode().decode("unicode_escape")
                elif directive == "set_separator":
                    set_separator = value
                elif directive == "empty_field":
                    empty = value
                elif directive == "unset_field":
                    unset = value
                elif directive == "path":
                    path = value
                elif directive == "fields":
                    fields = value.split(separator)
                continue
            payload = None
            if fields is not None:
                values = text.split(separator)
                record: dict[str, Any] = {}
                for name, value in zip(fields, values, strict=False):
                    if value == unset:
                        record[name] = None
                    elif value == empty:
                        record[name] = ""
                    elif set_separator in value and name in ("answers", "actions", "TTLs"):
                        record[name] = value.split(set_separator)
                    else:
                        record[name] = value
                payload = (record, path, len(values) == len(fields))
            yield RecordUnit(
                line.raw,
                self.ctx.encoding or "utf-8",
                line.locator(),
                payload=payload,
                full_hash=line.full_hash,
                warnings=line.warnings(),
            )

    def normalize(self, unit: RecordUnit) -> Normalized:
        if unit.payload is None:
            text = unit.raw.decode("utf-8", "replace")
            return Normalized(
                {"message": text, "extra": {}}, NO_TIMESTAMP, "unparsed", ["zeek_header_missing"]
            )
        record, path, complete = unit.payload
        result = zeek_normalize(record, _zeek_kind(record, path))
        if not complete:
            result.warnings.append("field_unparsed")
        return result


@register
class ZeekJsonParser(_Lines):
    format_id = "zeek_json"
    name = "network.zeek_json"
    version = VERSION
    source_type = "zeek"
    locator_kind = "json_line"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        try:
            record = json.loads(line.text)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            return self.unparsed(line, "json_invalid")
        kind = _zeek_kind(record, None)
        if kind == "unknown":
            kind = _zeek_path_from_filename(self.ctx.filename) or "unknown"
        return zeek_normalize(record, kind)


# --- CEF / LEEF ------------------------------------------------------------------------


def _split_header(text: str, count: int) -> tuple[list[str], str] | None:
    """Split pipe-delimited header fields, honoring \\| and \\\\ escapes."""
    fields: list[str] = []
    current: list[str] = []
    position = 0
    while position < len(text) and len(fields) < count:
        char = text[position]
        if char == "\\" and position + 1 < len(text) and text[position + 1] in "|\\":
            current.append(text[position + 1])
            position += 2
            continue
        if char == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        position += 1
    if len(fields) < count:
        return None
    return fields, text[position:]


_CEF_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]]+)=")
_CEF_UNESCAPE = {"\\=": "=", "\\\\": "\\", "\\n": "\n", "\\r": "\r"}


def _cef_extension(text: str) -> dict[str, str]:
    keys = list(_CEF_KEY.finditer(text))
    values: dict[str, str] = {}
    for index, match in enumerate(keys):
        # A key is only real if its '=' is not escaped.
        end = keys[index + 1].start() if index + 1 < len(keys) else len(text)
        raw = text[match.end() : end].rstrip()
        values[match.group(1)] = re.sub(r"\\[=\\nr]", lambda m: _CEF_UNESCAPE[m.group(0)], raw)
    return values


_DENY = ("deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected")
_ALLOW = ("allow", "allowed", "accept", "accepted", "permit", "permitted", "pass")
_RT_FORMATS = ("%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S.%f", "%b %d %H:%M:%S %Y")


def _action_outcome(action: str | None) -> tuple[str | None, str | None]:
    if not action:
        return None, None
    lowered = action.lower()
    if lowered in _DENY:
        return "connection_denied", "failure"
    if lowered in _ALLOW:
        return "connection_allowed", "success"
    return None, None


def _prefix_header(
    line_text: str, marker: int, parser: LinuxSyslogParser
) -> tuple[Timestamp, str | None]:
    """Timestamp and host from a syslog header in front of a CEF/LEEF payload."""
    prefix = line_text[:marker]
    match = _BSD.match(prefix + "x") or _ISO_HEADER.match(prefix + "x")
    if match is None:
        return NO_TIMESTAMP, None
    if "mon" in match.groupdict() and match["mon"]:
        return parser._bsd_timestamp(match), match["host"]
    return timeparse.parse_iso(match["ts"], parser.ctx.timezone_hint), match["host"]


class _SecurityEventParser(_Lines):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._syslog = LinuxSyslogParser(self.ctx)

    def _device_time(self, value: str | None) -> Timestamp | None:
        if not value:
            return None
        text = value.strip()
        if text.isdigit():
            # CEF rt/end in epoch milliseconds.
            return timeparse.from_epoch(text, Decimal(text) / 1000, "ms")
        stamp = timeparse.parse_iso(text, self.ctx.timezone_hint)
        if stamp.utc is not None or "timestamp_unparsed" not in stamp.warnings:
            return stamp
        return timeparse.parse_with_formats(text, _RT_FORMATS, self.ctx.timezone_hint)


@register
class CefParser(_SecurityEventParser):
    format_id = "cef"
    name = "network.cef"
    version = VERSION
    source_type = "cef"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        marker = line.text.find("CEF:")
        if marker == -1:
            return self.unparsed(line)
        header = _split_header(line.text[marker + 4 :], 7)
        if header is None:
            return self.unparsed(line)
        (version, vendor, product, device_version, signature, name, severity), rest = header
        ext = _cef_extension(rest)
        header_stamp, host = _prefix_header(line.text, marker, self._syslog)
        stamp = self._device_time(ext.get("rt") or ext.get("end")) or header_stamp
        event_type, outcome = _action_outcome(ext.get("act"))
        fields = {
            "hostname": ext.get("dvchost") or host,
            "username": ext.get("suser") or ext.get("duser"),
            "source_ip": ext.get("src"),
            "destination_ip": ext.get("dst"),
            "source_port": ext.get("spt"),
            "destination_port": ext.get("dpt"),
            "protocol": ext.get("proto") or ext.get("app"),
            "event_category": "network" if ext.get("src") or ext.get("dst") else None,
            "event_type": event_type or "cef_event",
            "event_outcome": outcome,
            "event_code": signature or None,
            "message": ext.get("msg") or name or None,
            "extra": {
                "cef_version": version,
                "device_vendor": vendor,
                "device_product": product,
                "device_version": device_version,
                "name": name,
                "severity": severity,
                "extension": ext,
            },
        }
        return Normalized(fields, stamp)


@register
class LeefParser(_SecurityEventParser):
    format_id = "leef"
    name = "network.leef"
    version = VERSION
    source_type = "leef"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        marker = line.text.find("LEEF:")
        if marker == -1:
            return self.unparsed(line)
        payload = line.text[marker + 5 :]
        version = payload.split("|", 1)[0]
        count = 6 if version.startswith("2") else 5
        header = _split_header(payload, count)
        if header is None:
            return self.unparsed(line)
        values, rest = header
        delimiter = "\t"
        if count == 6:
            spec = values[5]
            if spec.lower().startswith(("0x", "x")) and len(spec) > 1:
                try:
                    delimiter = chr(int(spec.lower().lstrip("0x") or "9", 16))
                except ValueError:
                    delimiter = "\t"
            elif spec:
                delimiter = spec
        attributes: dict[str, str] = {}
        for pair in rest.split(delimiter):
            key, sep, value = pair.partition("=")
            if sep:
                attributes[key.strip()] = value
        header_stamp, host = _prefix_header(line.text, marker, self._syslog)
        stamp = self._device_time(attributes.get("devTime")) or header_stamp
        event_type, outcome = _action_outcome(attributes.get("action") or attributes.get("cat"))
        fields = {
            "hostname": host,
            "username": attributes.get("usrName") or attributes.get("accountName"),
            "source_ip": attributes.get("src"),
            "destination_ip": attributes.get("dst"),
            "source_port": attributes.get("srcPort"),
            "destination_port": attributes.get("dstPort"),
            "protocol": attributes.get("proto"),
            "event_category": "network" if attributes.get("src") else None,
            "event_type": event_type or "leef_event",
            "event_outcome": outcome,
            "event_code": values[4] or None,
            "message": None,
            "extra": {
                "leef_version": values[0],
                "vendor": values[1],
                "product": values[2],
                "product_version": values[3],
                "attributes": attributes,
            },
        }
        if attributes.get("devTime") and stamp is header_stamp:
            return Normalized(fields, stamp, warnings=["device_time_unparsed"])
        return Normalized(fields, stamp)


# --- Squid -----------------------------------------------------------------------------

_SQUID = re.compile(
    r"^(?P<ts>\d{9,10}\.\d{3})\s+(?P<elapsed>-?\d+) (?P<client>\S+) (?P<action>[A-Z_]+)/"
    r"(?P<code>\d{3}) (?P<bytes>\d+) (?P<method>\S+) (?P<url>\S+) (?P<ident>\S+) "
    r"(?P<hier>[A-Z_]+)/(?P<peer>\S+)(?: (?P<type>\S+))?"
)


@register
class SquidParser(_Lines):
    format_id = "squid"
    name = "proxy.squid"
    version = VERSION
    source_type = "proxy"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        match = _SQUID.match(line.text)
        if not match:
            return self.unparsed(line)
        action = match["action"]
        outcome = (
            "failure" if "DENIED" in action else ("success" if match["code"][0] in "123" else None)
        )
        peer = none_if_dash(match["peer"])
        fields = {
            "source_ip": match["client"],
            "destination_ip": peer if peer and re.fullmatch(r"[0-9A-Fa-f:.]+", peer) else None,
            "username": none_if_dash(match["ident"]),
            "protocol": "http",
            "event_category": "web",
            "event_type": "proxy_request_denied" if "DENIED" in action else "proxy_request",
            "event_outcome": outcome,
            "event_code": match["code"],
            "message": line.text,
            "extra": {
                "cache_action": action,
                "elapsed_ms": int(match["elapsed"]),
                "response_bytes": int(match["bytes"]),
                "http_method": match["method"],
                "url": match["url"],
                "hierarchy": match["hier"],
                "peer": peer,
                "content_type": none_if_dash(match["type"]),
            },
        }
        stamp = timeparse.from_epoch(match["ts"], Decimal(match["ts"]), "ms")
        return Normalized(fields, stamp)
