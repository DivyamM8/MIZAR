"""Linux audit log (audit.log), raw and ENRICHED formats.

One audit event spans several records (SYSCALL, EXECVE, PATH, ... EOE) that
share msg=audit(<epoch>:<serial>). Records are grouped into one event per
serial; the locator lists every line, so the original lines stay traceable.
Groups are flushed at EOE, or when too many other serials have been seen
since (records of one event are normally adjacent).
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, BinaryIO

from mizar.parsers import timeparse
from mizar.parsers.base import (
    NO_TIMESTAMP,
    FileProblem,
    Normalized,
    Parser,
    RecordUnit,
    register,
)
from mizar.parsers.textio import Line, iter_lines

_HEADER = re.compile(
    r"^(?:node=(?P<node>\S+) )?type=(?P<type>[A-Z0-9_]+) "
    r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\): ?(?P<body>.*)$"
)
_KV = re.compile(r"""([A-Za-z0-9_-]+)=("[^"]*"|'[^']*'|\S+)""")
_HEX = re.compile(r"^(?:[0-9A-F]{2})+$")
# Fields auditd writes hex-encoded when they contain spaces or special characters.
_HEX_FIELDS = frozenset(
    {"proctitle", "name", "cmd", "comm", "exe", "cwd", "path", "data", "acct", "key", "ocomm"}
)
_MAX_PENDING_SERIALS = 64
_GROUP_SEPARATOR = "\x1d"  # ENRICHED format: interpreted fields follow this byte

_TYPE_MAP: dict[str, tuple[str, str]] = {
    "USER_LOGIN": ("authentication", "logon"),
    "USER_AUTH": ("authentication", "authentication"),
    "USER_ACCT": ("authentication", "account_check"),
    "USER_START": ("authentication", "session_opened"),
    "USER_END": ("authentication", "session_closed"),
    "USER_LOGOUT": ("authentication", "logoff"),
    "CRED_ACQ": ("authentication", "credentials_acquired"),
    "USER_CMD": ("privilege", "sudo_command"),
    "ADD_USER": ("account_management", "user_created"),
    "DEL_USER": ("account_management", "user_deleted"),
    "ADD_GROUP": ("account_management", "group_created"),
    "DEL_GROUP": ("account_management", "group_deleted"),
    "USER_MGMT": ("account_management", "user_modified"),
    "GRP_MGMT": ("account_management", "group_modified"),
    "USER_CHAUTHTOK": ("account_management", "password_changed"),
    "EXECVE": ("process", "process_executed"),
    "SERVICE_START": ("service", "service_started"),
    "SERVICE_STOP": ("service", "service_stopped"),
    "ANOM_ABEND": ("process", "process_crashed"),
    "CONFIG_CHANGE": ("system", "audit_config_changed"),
    "DAEMON_START": ("system", "audit_daemon_started"),
}
# Precedence when an event has several record types.
_PRIMARY_ORDER = (
    *_TYPE_MAP.keys(),
    "SYSCALL",
)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_fields(body: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return (raw fields, interpreted fields from the ENRICHED section)."""
    raw_part, _, enriched_part = body.partition(_GROUP_SEPARATOR)
    raw: dict[str, str] = {}
    for key, value in _KV.findall(raw_part):
        raw.setdefault(key, value)
    enriched = {key: _unquote(value) for key, value in _KV.findall(enriched_part)}
    return raw, enriched


def decode_value(key: str, value: str) -> tuple[str, bool]:
    """Unquote; hex-decode unquoted hex for fields auditd encodes. Returns (value, decoded)."""
    if value[:1] in "\"'":
        return _unquote(value), False
    if key in _HEX_FIELDS and _HEX.match(value):
        try:
            return bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", "replace"), True
        except ValueError:
            return value, False
    return value, False


@dataclass
class _Group:
    node: str | None
    epoch: str
    serial: str
    lines: list[Line] = field(default_factory=list)
    records: list[tuple[str, dict[str, str], dict[str, str]]] = field(default_factory=list)


@register
class AuditdParser(Parser):
    format_id = "auditd"
    name = "linux.auditd"
    version = "1.0.0"
    source_type = "auditd"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        pending: OrderedDict[tuple[str | None, str], _Group] = OrderedDict()
        for line in iter_lines(stream, self.ctx.encoding):
            match = _HEADER.match(line.text)
            if not match:
                yield RecordUnit(
                    line.raw,
                    self.ctx.encoding or "utf-8",
                    line.locator(),
                    payload=None,
                    full_hash=line.full_hash,
                    warnings=line.warnings(),
                )
                continue
            key = (match["node"], match["serial"])
            group = pending.get(key)
            if group is None:
                group = _Group(match["node"], match["epoch"], match["serial"])
                pending[key] = group
            raw_fields, enriched = parse_fields(match["body"])
            group.lines.append(line)
            group.records.append((match["type"], raw_fields, enriched))
            if match["type"] == "EOE":
                yield self._unit(pending.pop(key))
            while len(pending) > _MAX_PENDING_SERIALS:
                yield self._unit(pending.popitem(last=False)[1])
        for group in pending.values():
            yield self._unit(group)

    def _unit(self, group: _Group) -> RecordUnit:
        raw = b"\n".join(line.raw for line in group.lines)
        locator: dict[str, Any] = {
            "kind": "lines",
            "lines": [line.number for line in group.lines],
            "byte_ranges": [[line.offset, line.length] for line in group.lines],
        }
        warnings = sorted({w for line in group.lines for w in line.warnings()})
        return RecordUnit(raw, self.ctx.encoding or "utf-8", locator, group, warnings=warnings)

    def normalize(self, unit: RecordUnit) -> Normalized:
        group = unit.payload
        if not isinstance(group, _Group):
            text = unit.raw.decode("utf-8", "replace")
            return Normalized(
                {"message": text, "extra": {}},
                NO_TIMESTAMP,
                status="unparsed",
                warnings=["header_unparsed"],
            )
        types = [record_type for record_type, _, _ in group.records if record_type != "EOE"]
        merged: dict[str, str] = {}
        interpreted: dict[str, str] = {}
        decoded_raw: dict[str, str] = {}
        paths: list[str] = []
        execve_args: list[str] = []
        nested: dict[str, str] = {}
        for record_type, raw_fields, enriched in group.records:
            interpreted.update({k: v for k, v in enriched.items() if k not in interpreted})
            for key, value in raw_fields.items():
                if key == "msg" and value.startswith("'"):
                    # USER_* records nest their details in msg='...'.
                    inner, inner_enriched = parse_fields(_unquote(value))
                    for inner_key, inner_value in inner.items():
                        nested.setdefault(inner_key, decode_value(inner_key, inner_value)[0])
                    interpreted.update(inner_enriched)
                    continue
                decoded, was_hex = decode_value(key, value)
                if was_hex:
                    decoded_raw[f"{key}_hex"] = value
                if record_type == "PATH" and key == "name":
                    paths.append(decoded)
                elif record_type == "EXECVE" and re.fullmatch(r"a\d+", key):
                    execve_args.append(decoded if was_hex else _unquote(value))
                else:
                    merged.setdefault(key, decoded)
        values = {**merged, **nested}

        primary = next((t for t in _PRIMARY_ORDER if t in types), types[0] if types else "")
        category, event_type = _TYPE_MAP.get(primary, ("system", f"audit_{primary.lower()}"))
        if primary == "SYSCALL" and values.get("key") not in (None, "(null)"):
            category, event_type = "file" if paths else "system", "audit_watch_triggered"
        result = values.get("res") or values.get("success")
        outcome = {
            "success": "success",
            "yes": "success",
            "failed": "failure",
            "no": "failure",
        }.get((result or "").lower())
        if event_type == "logon" and outcome == "failure":
            event_type = "logon_failed"

        address = values.get("addr")
        username = values.get("acct") or interpreted.get("AUID") or interpreted.get("UID")
        if username in ("unset", "(unknown)", "?"):
            username = None
        stamp = timeparse.from_epoch(
            f"{group.epoch}:{group.serial}",
            Decimal(group.epoch),
            timeparse.precision_for(len(group.epoch.partition(".")[2])),
        )
        extra: dict[str, Any] = {
            "audit_serial": group.serial,
            "record_types": types,
            "fields": {k: v for k, v in values.items() if k not in ("addr", "acct")},
            **({"interpreted": interpreted} if interpreted else {}),
            **({"paths": paths} if paths else {}),
            **({"execve_args": execve_args} if execve_args else {}),
            **({"hex_originals": decoded_raw} if decoded_raw else {}),
            **({"audit_key": values["key"]} if values.get("key") not in (None, "(null)") else {}),
        }
        hostname_field = values.get("hostname")
        if hostname_field and hostname_field not in ("?", address):
            extra["remote_hostname"] = hostname_field
        fields = {
            "hostname": group.node,
            "username": username,
            "source_ip": address if address not in (None, "?") else None,
            "event_category": category,
            "event_type": event_type,
            "event_outcome": outcome,
            "event_code": primary or None,
            "process_name": values.get("exe") or values.get("comm"),
            "process_id": values.get("pid"),
            "session_id": None if values.get("ses") in (None, "4294967295") else values["ses"],
            "message": unit.raw.decode("utf-8", "replace"),
            "extra": extra,
        }
        return Normalized(fields, stamp)
