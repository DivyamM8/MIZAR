"""Windows event logs: native .evtx and XML / JSON / Event Viewer CSV exports.

Every input is first turned into a WinEvent, then mapped by one function, so
an event means the same thing whichever export it came from. EventData is
always kept complete in extra.event_data; the core fields are only filled
from named EventData values whose meaning is fixed by the event definition.
Exports with positional (unnamed) data or no data at all (Event Viewer CSV)
are marked partial instead of guessing which value is which.
"""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, BinaryIO

from mizar.parsers import timeparse
from mizar.parsers.base import (
    NO_TIMESTAMP,
    FileParseError,
    FileProblem,
    Normalized,
    Parser,
    RecordUnit,
    Timestamp,
    none_if_dash,
    register,
)
from mizar.parsers.textio import (
    MAX_JSON_ITEM_CHARS,
    JsonArrayError,
    decoded_chunks,
    iter_json_array,
    iter_lines,
)

VERSION = "1.0.0"
SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
SCM = "Service Control Manager"
SYSMON = "Microsoft-Windows-Sysmon"
POWERSHELL = ("Microsoft-Windows-PowerShell", "PowerShell")


@dataclass
class WinEvent:
    provider: str | None = None
    event_id: int | None = None
    channel: str | None = None
    computer: str | None = None
    record_id: int | None = None
    system_time: str | None = None
    system: dict[str, Any] = field(default_factory=dict)
    event_data: dict[str, Any] | None = None
    event_data_values: list[Any] | None = None
    user_data: dict[str, Any] | None = None
    message: str | None = None


def _int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _split_account(value: Any) -> tuple[str | None, str | None]:
    """'DOMAIN\\user' -> (user, DOMAIN)."""
    text = none_if_dash(value)
    if text is None:
        return None, None
    text = str(text)
    if "\\" in text:
        domain, user = text.split("\\", 1)
        return user or None, domain or None
    return text, None


# --- event mapping ---------------------------------------------------------------------

_GROUP_SCOPE = {4728: "global", 4732: "local", 4756: "universal"}
_SECURITY_SIMPLE: dict[int, tuple[str, str, str | None]] = {
    4634: ("authentication", "logoff", "success"),
    4647: ("authentication", "logoff", "success"),
    4699: ("scheduled_task", "scheduled_task_deleted", "success"),
    4702: ("scheduled_task", "scheduled_task_updated", "success"),
    4722: ("account_management", "user_enabled", "success"),
    4723: ("account_management", "password_change_attempted", None),
    4724: ("account_management", "password_reset", None),
    4725: ("account_management", "user_disabled", "success"),
    4726: ("account_management", "user_deleted", "success"),
    4738: ("account_management", "user_modified", "success"),
    4729: ("account_management", "group_member_removed", "success"),
    4733: ("account_management", "group_member_removed", "success"),
    4757: ("account_management", "group_member_removed", "success"),
    4768: ("authentication", "kerberos_tgt_requested", None),
    4769: ("authentication", "kerberos_service_ticket_requested", None),
    4771: ("authentication", "kerberos_preauth_failed", "failure"),
}


def _security_fields(event_id: int, data: dict[str, Any]) -> dict[str, Any]:
    def get(name: str) -> Any:
        return none_if_dash(data.get(name))

    fields: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    target = {"username": get("TargetUserName"), "user_domain": get("TargetDomainName")}
    subject = {"username": get("SubjectUserName"), "user_domain": get("SubjectDomainName")}
    network = {"source_ip": get("IpAddress"), "source_port": get("IpPort")}
    if event_id == 4624:
        fields = {
            "event_category": "authentication",
            "event_type": "logon",
            "event_outcome": "success",
            **target,
            **network,
            "session_id": get("TargetLogonId"),
            "process_name": get("ProcessName"),
        }
        extra = {"logon_type": _int(get("LogonType")), "workstation": get("WorkstationName")}
    elif event_id == 4625:
        fields = {
            "event_category": "authentication",
            "event_type": "logon_failed",
            "event_outcome": "failure",
            **target,
            **network,
            "process_name": get("ProcessName"),
        }
        extra = {
            "logon_type": _int(get("LogonType")),
            "status": get("Status"),
            "sub_status": get("SubStatus"),
            "workstation": get("WorkstationName"),
        }
    elif event_id == 4648:
        fields = {
            "event_category": "authentication",
            "event_type": "explicit_credential_logon",
            "event_outcome": "success",
            **target,
            **network,
            "session_id": get("SubjectLogonId"),
            "process_name": get("ProcessName"),
        }
        extra = {"subject_user": get("SubjectUserName"), "target_server": get("TargetServerName")}
    elif event_id == 4672:
        fields = {
            "event_category": "privilege",
            "event_type": "special_privileges_assigned",
            "event_outcome": "success",
            **subject,
            "session_id": get("SubjectLogonId"),
        }
        extra = {"privileges": get("PrivilegeList")}
    elif event_id == 4688:
        fields = {
            "event_category": "process",
            "event_type": "process_created",
            "event_outcome": "success",
            **subject,
            "session_id": get("SubjectLogonId"),
            "process_name": get("NewProcessName"),
            "process_id": _int(get("NewProcessId")),
        }
        extra = {"command_line": get("CommandLine"), "parent_process": get("ParentProcessName")}
    elif event_id == 4697:
        fields = {
            "event_category": "service",
            "event_type": "service_installed",
            "event_outcome": "success",
            **subject,
            "session_id": get("SubjectLogonId"),
        }
        extra = {"service_name": get("ServiceName"), "service_file": get("ServiceFileName")}
    elif event_id == 4698:
        fields = {
            "event_category": "scheduled_task",
            "event_type": "scheduled_task_created",
            "event_outcome": "success",
            **subject,
            "session_id": get("SubjectLogonId"),
        }
        extra = {"task_name": get("TaskName")}
    elif event_id == 4720:
        fields = {
            "event_category": "account_management",
            "event_type": "user_created",
            "event_outcome": "success",
            **target,
            "session_id": get("SubjectLogonId"),
        }
        extra = {"actor": get("SubjectUserName"), "actor_domain": get("SubjectDomainName")}
    elif event_id in _GROUP_SCOPE:
        member, member_domain = _split_account(get("MemberName"))
        fields = {
            "event_category": "account_management",
            "event_type": "group_member_added",
            "event_outcome": "success",
            # The member is often only a SID (MemberName "-" for local groups).
            "username": member or get("MemberSid"),
            "user_domain": member_domain,
            "session_id": get("SubjectLogonId"),
        }
        extra = {
            "group_name": get("TargetUserName"),
            "group_domain": get("TargetDomainName"),
            "group_sid": get("TargetSid"),
            "group_scope": _GROUP_SCOPE[event_id],
            "member_sid": get("MemberSid"),
            "actor": get("SubjectUserName"),
        }
    elif event_id == 4740:
        fields = {
            "event_category": "authentication",
            "event_type": "account_locked_out",
            "event_outcome": None,
            "username": get("TargetUserName"),
        }
    elif event_id == 4776:
        status = get("Status")
        fields = {
            "event_category": "authentication",
            "event_type": "credential_validation",
            "event_outcome": None
            if status is None
            else ("success" if status == "0x0" else "failure"),
            "username": get("TargetUserName"),
        }
        extra = {"workstation": get("Workstation"), "status": status}
    elif event_id in _SECURITY_SIMPLE:
        category, event_type, outcome = _SECURITY_SIMPLE[event_id]
        user = target if target["username"] else subject
        fields = {
            "event_category": category,
            "event_type": event_type,
            "event_outcome": outcome,
            **user,
            **network,
            "session_id": get("TargetLogonId") or get("SubjectLogonId"),
        }
        if event_id in (4729, 4733, 4757):
            member, _ = _split_account(get("MemberName"))
            fields["username"] = member or get("MemberSid")
            extra = {"group_name": get("TargetUserName")}
    fields["extra"] = {k: v for k, v in extra.items() if v is not None}
    return fields


def _sysmon_fields(event_id: int, data: dict[str, Any]) -> dict[str, Any]:
    def get(name: str) -> Any:
        return none_if_dash(data.get(name))

    user, domain = _split_account(get("User"))
    base = {
        "username": user,
        "user_domain": domain,
        "process_name": get("Image"),
        "process_id": _int(get("ProcessId")),
    }
    if event_id == 1:
        return {
            **base,
            "event_category": "process",
            "event_type": "process_created",
            "event_outcome": "success",
            "extra": {
                "command_line": get("CommandLine"),
                "parent_image": get("ParentImage"),
                "parent_command_line": get("ParentCommandLine"),
                "process_guid": get("ProcessGuid"),
                "parent_process_guid": get("ParentProcessGuid"),
                "hashes": get("Hashes"),
            },
        }
    if event_id == 3:
        return {
            **base,
            "event_category": "network",
            "event_type": "network_connection",
            "event_outcome": None,
            "source_ip": get("SourceIp"),
            "source_port": get("SourcePort"),
            "destination_ip": get("DestinationIp"),
            "destination_port": get("DestinationPort"),
            "protocol": get("Protocol"),
            "extra": {
                "initiated": get("Initiated"),
                "destination_hostname": get("DestinationHostname"),
            },
        }
    simple = {
        11: ("file", "file_created", {"target_filename": get("TargetFilename")}),
        13: ("system", "registry_value_set", {"target_object": get("TargetObject")}),
        12: ("system", "registry_object_changed", {"target_object": get("TargetObject")}),
        10: ("process", "process_accessed", {"target_image": get("TargetImage")}),
        22: ("network", "dns_query", {"query_name": get("QueryName")}),
    }
    if event_id in simple:
        category, event_type, extra = simple[event_id]
        return {**base, "event_category": category, "event_type": event_type, "extra": extra}
    return {**base, "event_type": f"sysmon_event_{event_id}", "extra": {}}


def map_event(win: WinEvent) -> tuple[dict[str, Any], list[str]]:
    """Core fields for a WinEvent. Returns (fields, warnings)."""
    warnings: list[str] = []
    data = win.event_data or {}
    user_data = win.user_data or {}
    event_id = win.event_id
    fields: dict[str, Any] = {}
    if event_id is not None and win.event_data_values is not None and not data:
        warnings.append("event_data_positional")
    if event_id is None:
        pass
    elif win.provider == SECURITY:
        fields = _security_fields(event_id, data)
    elif win.provider == EVENTLOG and event_id in (1102, 104):
        subject = none_if_dash(user_data.get("SubjectUserName"))
        fields = {
            "event_category": "system",
            "event_type": "audit_log_cleared" if event_id == 1102 else "log_cleared",
            "event_outcome": "success",
            "username": subject,
            "user_domain": none_if_dash(user_data.get("SubjectDomainName")),
            "session_id": none_if_dash(user_data.get("SubjectLogonId")),
            "extra": {"cleared_channel": user_data.get("Channel")} if event_id == 104 else {},
        }
    elif win.provider == SCM and event_id == 7045:
        fields = {
            "event_category": "service",
            "event_type": "service_installed",
            "event_outcome": "success",
            "extra": {
                "service_name": none_if_dash(data.get("ServiceName")),
                "image_path": none_if_dash(data.get("ImagePath")),
                "service_account": none_if_dash(data.get("AccountName")),
                "start_type": none_if_dash(data.get("StartType")),
            },
        }
    elif win.provider == SYSMON:
        fields = _sysmon_fields(event_id, data)
    elif win.provider in POWERSHELL and event_id in (4103, 4104):
        fields = {
            "event_category": "process",
            "event_type": "powershell_script_block"
            if event_id == 4104
            else "powershell_pipeline_executed",
            "extra": {"script_path": none_if_dash(data.get("Path"))} if event_id == 4104 else {},
        }
    if not fields.get("event_type") and event_id is not None:
        fields["event_type"] = f"windows_event_{event_id}"
    extra = dict(fields.pop("extra", {}) or {})
    extra.update(
        {
            "provider": win.provider,
            "channel": win.channel,
            "record_id": win.record_id,
            "system": win.system,
        }
    )
    if win.event_data is not None:
        extra["event_data"] = win.event_data
    if win.event_data_values is not None:
        extra["event_data_values"] = win.event_data_values
    if win.user_data is not None:
        extra["user_data"] = win.user_data
    fields["extra"] = extra
    fields["hostname"] = win.computer
    fields["event_code"] = None if event_id is None else str(event_id)
    fields["message"] = win.message
    return fields, warnings


def _normalize(
    win: WinEvent, stamp: Timestamp, extra_warnings: list[str] | None = None
) -> Normalized:
    fields, warnings = map_event(win)
    warnings.extend(extra_warnings or [])
    if win.event_id is None:
        return Normalized(fields, stamp, status="partial", warnings=[*warnings, "field_unparsed"])
    return Normalized(fields, stamp, warnings=warnings)


# --- evtx JSON shape (pyevtx-rs / evtx_dump) --------------------------------------------


def _attrs(node: Any) -> dict[str, Any]:
    if isinstance(node, dict):
        attributes = node.get("#attributes")
        if isinstance(attributes, dict):
            return attributes
    return {}


def _text(node: Any) -> Any:
    if isinstance(node, dict):
        return node.get("#text")
    return node


def from_evtx_json(document: dict[str, Any]) -> WinEvent:
    event = document.get("Event", document)
    system = event.get("System") or {}
    win = WinEvent(
        provider=_attrs(system.get("Provider")).get("Name"),
        event_id=_int(_text(system.get("EventID"))),
        channel=system.get("Channel"),
        computer=system.get("Computer"),
        record_id=_int(system.get("EventRecordID")),
        system_time=_attrs(system.get("TimeCreated")).get("SystemTime"),
    )
    execution = _attrs(system.get("Execution"))
    win.system = {
        "version": system.get("Version"),
        "level": system.get("Level"),
        "task": system.get("Task"),
        "opcode": system.get("Opcode"),
        "keywords": system.get("Keywords"),
        "logging_process_id": execution.get("ProcessID"),
        "thread_id": execution.get("ThreadID"),
        "user_sid": _attrs(system.get("Security")).get("UserID"),
    }
    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        named = {k: _text(v) for k, v in event_data.items() if k not in ("#attributes", "Data")}
        positional = event_data.get("Data")
        if named:
            win.event_data = named
        if positional is not None:
            values = _text(positional)
            win.event_data_values = values if isinstance(values, list) else [values]
    user_data = event.get("UserData")
    if isinstance(user_data, dict) and user_data:
        inner = next(iter(user_data.values()))
        if isinstance(inner, dict):
            win.user_data = {k: _text(v) for k, v in inner.items() if k != "#attributes"}
    rendering = event.get("RenderingInfo")
    if isinstance(rendering, dict) and isinstance(rendering.get("Message"), str):
        win.message = rendering["Message"]
    return win


@register
class WindowsEvtxParser(Parser):
    format_id = "windows_evtx"
    name = "windows.evtx"
    version = VERSION
    source_type = "windows_evtx"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        from evtx import PyEvtxParser

        try:
            parser = PyEvtxParser(str(self.ctx.blob_path))
            records = parser.records_json()
        except (OSError, RuntimeError, ValueError) as exc:
            raise FileParseError(
                "EVTX_CORRUPT_HEADER", f"EVTX file cannot be opened: {exc}"
            ) from exc
        index = 0
        while True:
            try:
                record = next(records)
            except StopIteration:
                return
            except (RuntimeError, ValueError, OSError) as exc:
                # The library skips the damaged chunk and continues with the next one.
                yield FileProblem(
                    "EVTX_CHUNK_UNREADABLE",
                    "Part of the EVTX file could not be read; its records are missing.",
                    {"error": str(exc)[:300]},
                )
                continue
            if not isinstance(record, dict):
                continue
            data: str = record["data"]
            # Damaged files can repeat record IDs; the position keeps locators unique.
            yield RecordUnit(
                data.encode("utf-8"),
                "evtx-json-rendering",
                {"kind": "evtx_record", "record_id": record["event_record_id"], "index": index},
                payload=data,
            )
            index += 1

    def normalize(self, unit: RecordUnit) -> Normalized:
        win = from_evtx_json(json.loads(unit.payload))
        if win.system_time is None:
            stamp = NO_TIMESTAMP
        else:
            parsed = timeparse.parse_iso(win.system_time, None)
            # EVTX stores FILETIME (UTC); the rendered text carries the Z suffix.
            stamp = Timestamp(
                parsed.original,
                parsed.utc,
                parsed.precision,
                "format_defined_utc" if parsed.utc else parsed.assumption,
                parsed.warnings,
            )
        return _normalize(win, stamp)


# --- XML exports -----------------------------------------------------------------------

_EVENT_START = re.compile(r"<Event[\s>]")
_EVENT_END = "</Event>"
_FORBIDDEN_XML = ("<!DOCTYPE", "<!ENTITY")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def from_xml(element: ET.Element) -> WinEvent:
    win = WinEvent()
    system_children = {}
    for child in element:
        name = _local(child.tag)
        if name == "System":
            system_children = {_local(c.tag): c for c in child}
        elif name == "EventData":
            named: dict[str, Any] = {}
            positional: list[Any] = []
            for data in child:
                key = data.get("Name")
                if key:
                    named[key] = data.text
                else:
                    positional.append(data.text)
            win.event_data = named or None
            win.event_data_values = positional or None
        elif name == "UserData" and len(child):
            win.user_data = {_local(c.tag): c.text for c in child[0]}
        elif name == "RenderingInfo":
            message = next((c for c in child if _local(c.tag) == "Message"), None)
            win.message = message.text if message is not None else None
    provider = system_children.get("Provider")
    win.provider = provider.get("Name") if provider is not None else None

    def text(name: str) -> str | None:
        node = system_children.get(name)
        return node.text if node is not None else None

    def attr(name: str, key: str) -> str | None:
        node = system_children.get(name)
        return node.get(key) if node is not None else None

    win.event_id = _int(text("EventID"))
    win.channel = text("Channel")
    win.computer = text("Computer")
    win.record_id = _int(text("EventRecordID"))
    win.system_time = attr("TimeCreated", "SystemTime")
    win.system = {
        "version": text("Version"),
        "level": text("Level"),
        "task": text("Task"),
        "opcode": text("Opcode"),
        "keywords": text("Keywords"),
        "logging_process_id": attr("Execution", "ProcessID"),
        "thread_id": attr("Execution", "ThreadID"),
        "user_sid": attr("Security", "UserID"),
    }
    return win


def _export_timestamp(win: WinEvent, timezone_hint: str | None) -> Timestamp:
    if win.system_time is None:
        return NO_TIMESTAMP
    return timeparse.parse_iso(win.system_time, timezone_hint)


@register
class WindowsEvtxXmlParser(Parser):
    format_id = "windows_evtx_xml"
    name = "windows.evtx_xml"
    version = VERSION
    source_type = "windows_evtx_export"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        encoding = self.ctx.encoding or "utf-8"
        text_encoding = "utf-8" if encoding == "utf-8-sig" else encoding
        buffer = ""
        base = 0
        index = 0
        for chunk in decoded_chunks(stream, encoding):
            buffer += chunk
            while True:
                start = _EVENT_START.search(buffer)
                if start is None:
                    keep = min(len(buffer), len("<Event "))
                    base += len(buffer) - keep
                    buffer = buffer[-keep:] if keep else ""
                    break
                end = buffer.find(_EVENT_END, start.start())
                if end == -1:
                    if len(buffer) - start.start() > MAX_JSON_ITEM_CHARS:
                        raise FileParseError(
                            "XML_EVENT_TOO_LARGE", "An <Event> element is too large."
                        )
                    base += start.start()
                    buffer = buffer[start.start() :]
                    break
                stop = end + len(_EVENT_END)
                span = buffer[start.start() : stop]
                yield RecordUnit(
                    span.encode(text_encoding),
                    encoding,
                    {
                        "kind": "xml_event",
                        "index": index,
                        "char_offset": base + start.start(),
                        "char_length": len(span),
                    },
                    payload=span,
                )
                index += 1
                base += stop
                buffer = buffer[stop:]

    def normalize(self, unit: RecordUnit) -> Normalized:
        span: str = unit.payload
        if any(marker in span for marker in _FORBIDDEN_XML):
            return Normalized(
                {"message": None, "extra": {}}, NO_TIMESTAMP, "unparsed", ["xml_doctype_refused"]
            )
        try:
            # stdlib expat on 3.14 resists entity expansion and never fetches external
            # entities; DOCTYPE/ENTITY declarations are refused above as well.
            element = ET.fromstring(span)  # noqa: S314
        except ET.ParseError:
            return Normalized(
                {"message": None, "extra": {}}, NO_TIMESTAMP, "unparsed", ["xml_invalid"]
            )
        win = from_xml(element)
        return _normalize(win, _export_timestamp(win, self.ctx.timezone_hint))


# --- JSON exports ----------------------------------------------------------------------

_DOTNET_DATE = re.compile(r"^/Date\((?P<ms>-?\d+)(?:[+-]\d{4})?\)/$")


def from_get_winevent(item: dict[str, Any]) -> tuple[WinEvent, Timestamp | None]:
    """Get-WinEvent | ConvertTo-Json. Properties are positional (no names)."""
    win = WinEvent(
        provider=item.get("ProviderName"),
        event_id=_int(item.get("Id")),
        channel=item.get("LogName"),
        computer=item.get("MachineName"),
        record_id=_int(item.get("RecordId")),
        message=item.get("Message") if isinstance(item.get("Message"), str) else None,
    )
    user_id = item.get("UserId")
    win.system = {
        "version": item.get("Version"),
        "level": item.get("Level"),
        "task": item.get("Task"),
        "keywords": item.get("Keywords"),
        "logging_process_id": item.get("ProcessId"),
        "thread_id": item.get("ThreadId"),
        "user_sid": user_id.get("Value") if isinstance(user_id, dict) else user_id,
    }
    properties = item.get("Properties")
    if isinstance(properties, list):
        win.event_data_values = [p.get("Value") if isinstance(p, dict) else p for p in properties]
    created = item.get("TimeCreated")
    if isinstance(created, str):
        dotnet = _DOTNET_DATE.match(created)
        if dotnet:
            return win, timeparse.from_epoch(created, Decimal(dotnet["ms"]) / 1000, "ms")
        win.system_time = created
    elif isinstance(created, dict) and isinstance(created.get("value"), str):
        win.system_time = created["value"]
    return win, None


@register
class WindowsEvtxJsonParser(Parser):
    format_id = "windows_evtx_json"
    name = "windows.evtx_json"
    version = VERSION
    source_type = "windows_evtx_export"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        encoding = self.ctx.encoding or "utf-8"
        text_encoding = "utf-8" if encoding == "utf-8-sig" else encoding
        head = stream.read(4096)
        stream.seek(0)
        first = head.decode(text_encoding, "ignore").lstrip("\ufeff \t\r\n")[:1]
        if first == "[":
            try:
                for index, offset, text, item in iter_json_array(decoded_chunks(stream, encoding)):
                    yield RecordUnit(
                        text.encode(text_encoding),
                        encoding,
                        {"kind": "json_array_item", "index": index, "char_offset": offset},
                        payload=item,
                    )
            except JsonArrayError as exc:
                raise FileParseError("JSON_INVALID", f"The JSON array is malformed: {exc}") from exc
            return
        for line in iter_lines(stream, encoding):
            try:
                value: Any = json.loads(line.text)
            except ValueError:
                value = None
            locator = {**line.locator(), "kind": "json_line"}
            yield RecordUnit(line.raw, encoding, locator, value, line.full_hash, line.warnings())

    def normalize(self, unit: RecordUnit) -> Normalized:
        item = unit.payload
        if not isinstance(item, dict):
            text = unit.raw.decode("utf-8", "replace")
            return Normalized(
                {"message": text, "extra": {}}, NO_TIMESTAMP, "unparsed", ["json_invalid"]
            )
        if "Event" in item or "System" in item:
            win = from_evtx_json(item)
            return _normalize(win, _export_timestamp(win, self.ctx.timezone_hint))
        win, stamp = from_get_winevent(item)
        return _normalize(win, stamp or _export_timestamp(win, self.ctx.timezone_hint))


# --- Event Viewer CSV ------------------------------------------------------------------

# Event Viewer writes local time without offset, in the exporting machine's locale.
# Only unambiguous layouts are accepted; anything else stays unparsed.
_CSV_TIME_FORMATS = ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")


@dataclass
class _CsvRow:
    values: list[str]
    header: list[str]


def _text_lines(stream: BinaryIO, encoding: str) -> Iterator[tuple[int, str]]:
    """Lines including blank ones and terminators (CSV fields may span lines)."""
    pending = ""
    number = 0
    for chunk in decoded_chunks(stream, encoding):
        pending += chunk
        parts = pending.splitlines(keepends=True)
        pending = parts.pop() if parts and not parts[-1].endswith(("\n", "\r")) else ""
        for part in parts:
            number += 1
            yield number, part
    if pending:
        yield number + 1, pending


@register
class WindowsEvtxCsvParser(Parser):
    format_id = "windows_evtx_csv"
    name = "windows.evtx_csv"
    version = VERSION
    source_type = "windows_evtx_export"

    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]:
        encoding = self.ctx.encoding or "utf-8"
        text_encoding = "utf-8" if encoding == "utf-8-sig" else encoding
        consumed: list[tuple[int, str]] = []
        lines = _text_lines(stream, encoding)

        def feed() -> Iterator[str]:
            for number, text in lines:
                consumed.append((number, text))
                yield text

        reader = csv.reader(feed())
        header: list[str] | None = None
        row_number = 0
        try:
            for values in reader:
                span = consumed[:]
                consumed.clear()
                if header is None:
                    header = values
                    continue
                if not values or not any(v.strip() for v in values):
                    continue
                raw_text = "".join(text for _, text in span).rstrip("\r\n")
                row_number += 1
                yield RecordUnit(
                    raw_text.encode(text_encoding),
                    encoding,
                    {"kind": "csv_row", "row": row_number, "line": span[0][0] if span else None},
                    payload=_CsvRow(values, header),
                )
        except csv.Error as exc:
            raise FileParseError("CSV_INVALID", f"The CSV file is malformed: {exc}") from exc

    def normalize(self, unit: RecordUnit) -> Normalized:
        row: _CsvRow = unit.payload
        columns = dict(zip(row.header, row.values, strict=False))
        overflow = row.values[len(row.header) :]
        win = WinEvent(
            provider=columns.get("Source"),
            event_id=_int(columns.get("Event ID")),
            message="\n".join(overflow) if overflow else None,
        )
        win.system = {"level": columns.get("Level"), "task_category": columns.get("Task Category")}
        original = columns.get("Date and Time")
        stamp = (
            timeparse.parse_with_formats(original, _CSV_TIME_FORMATS, self.ctx.timezone_hint)
            if original
            else NO_TIMESTAMP
        )
        # Event Viewer CSV contains only the rendered message, no event data.
        return _normalize(win, stamp, ["event_data_unavailable"])
