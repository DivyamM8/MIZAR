"""Supported input formats. Parsers (Phase 2) register against these IDs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FormatInfo:
    format_id: str
    label: str
    family: str


_FORMATS = (
    FormatInfo("windows_evtx", "Windows Event Log (.evtx)", "windows"),
    FormatInfo("windows_evtx_xml", "Windows events exported as XML", "windows"),
    FormatInfo("windows_evtx_json", "Windows events exported as JSON", "windows"),
    FormatInfo("windows_evtx_csv", "Windows Event Viewer CSV export", "windows"),
    FormatInfo("linux_syslog", "Syslog (traditional / rsyslog file format)", "linux"),
    FormatInfo("syslog_rfc5424", "Syslog RFC 5424", "linux"),
    FormatInfo("journald_json", "journald JSON export", "linux"),
    FormatInfo("auditd", "Linux audit log", "linux"),
    FormatInfo("web_access", "Apache/Nginx access log", "web_network"),
    FormatInfo("zeek_tsv", "Zeek log (TSV)", "web_network"),
    FormatInfo("zeek_json", "Zeek log (JSON)", "web_network"),
    FormatInfo("cef", "Common Event Format (CEF)", "web_network"),
    FormatInfo("leef", "Log Event Extended Format (LEEF)", "web_network"),
    FormatInfo("squid", "Squid proxy access log", "web_network"),
    FormatInfo("generic_jsonl", "Unrecognized JSON lines (generic parser)", "generic"),
    FormatInfo("generic_text", "Unrecognized text (generic parser)", "generic"),
)

FORMATS: dict[str, FormatInfo] = {fmt.format_id: fmt for fmt in _FORMATS}
GENERIC_FORMATS = frozenset({"generic_jsonl", "generic_text"})


def is_known_format(format_id: str) -> bool:
    return format_id in FORMATS
