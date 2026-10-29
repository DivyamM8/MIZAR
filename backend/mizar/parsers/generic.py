"""Generic fallback parsers (DESIGN.md §7.4) for files no specific parser recognizes.

They extract only what is unambiguous: a timestamp in a common layout and
the IP addresses that appear. The role of an IP (source or destination) is
unknown here, so IPs go to extra.ips_found, never to source_ip.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from mizar.parsers import timeparse
from mizar.parsers.base import NO_TIMESTAMP, Normalized, RecordUnit, Timestamp, register
from mizar.parsers.network import _Lines
from mizar.parsers.syslog import _BSD, LinuxSyslogParser
from mizar.parsers.textio import Line

VERSION = "1.0.0"
_ISO_IN_TEXT = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
)
_EPOCH_START = re.compile(r"^(?P<epoch>\d{10}(?:\.\d{1,6})?)\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_TIME_KEYS = ("@timestamp", "timestamp", "time", "ts", "datetime", "date", "eventTime", "Timestamp")
_MESSAGE_KEYS = ("message", "msg", "log", "Message", "MESSAGE")
_HOST_KEYS = ("host", "hostname", "Hostname", "computer", "Computer")
_MAX_IPS = 20


def find_ips(text: str) -> list[str]:
    found: list[str] = []
    for match in (*_IPV4.finditer(text), *_IPV6.finditer(text)):
        try:
            address = str(ipaddress.ip_address(match.group(0)))
        except ValueError:
            continue
        if address not in found:
            found.append(address)
        if len(found) >= _MAX_IPS:
            break
    return found


def _timestamp_in_text(text: str, syslog: LinuxSyslogParser, hint: str | None) -> Timestamp:
    iso = _ISO_IN_TEXT.search(text[:200])
    if iso:
        return timeparse.parse_iso(iso.group(0), hint)
    bsd = _BSD.match(text)
    if bsd:
        return syslog._bsd_timestamp(bsd)
    epoch = _EPOCH_START.match(text)
    if epoch:
        value = epoch["epoch"]
        return timeparse.from_epoch(
            value, value, timeparse.precision_for(len(value.partition(".")[2]))
        )
    return NO_TIMESTAMP


@register
class GenericTextParser(_Lines):
    format_id = "generic_text"
    name = "generic.text"
    version = VERSION
    source_type = "generic"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._syslog = LinuxSyslogParser(self.ctx)

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        stamp = _timestamp_in_text(line.text, self._syslog, self.ctx.timezone_hint)
        extra: dict[str, Any] = {}
        ips = find_ips(line.text)
        if ips:
            extra["ips_found"] = ips
        status = "unparsed" if stamp.original is None else "partial"
        return Normalized({"message": line.text, "extra": extra}, stamp, status=status)


@register
class GenericJsonLinesParser(_Lines):
    format_id = "generic_jsonl"
    name = "generic.jsonl"
    version = VERSION
    source_type = "generic"
    locator_kind = "json_line"

    def normalize(self, unit: RecordUnit) -> Normalized:
        line: Line = unit.payload
        try:
            record = json.loads(line.text)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            return Normalized(
                {"message": line.text, "extra": {}}, NO_TIMESTAMP, "unparsed", ["json_invalid"]
            )
        stamp = NO_TIMESTAMP
        for key in _TIME_KEYS:
            value = record.get(key)
            if isinstance(value, str):
                stamp = timeparse.parse_iso(value, self.ctx.timezone_hint)
                break
            if isinstance(value, int | float) and not isinstance(value, bool):
                stamp = timeparse.from_epoch(str(value), str(value), "s")
                break
        message = next((record[k] for k in _MESSAGE_KEYS if isinstance(record.get(k), str)), None)
        host = next((record[k] for k in _HOST_KEYS if isinstance(record.get(k), str)), None)
        extra: dict[str, Any] = {"json": record}
        ips = find_ips(line.text)
        if ips:
            extra["ips_found"] = ips
        fields = {"hostname": host, "message": message, "extra": extra}
        return Normalized(fields, stamp, status="partial")
