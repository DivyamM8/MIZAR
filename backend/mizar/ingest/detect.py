"""Content-based format detection (DESIGN.md §6.1 step 5).

Only the first 64 KiB are inspected. Every detector reports a score in [0, 1]
and a reason; all candidates are kept so the analyst can see why a format won
and override it. File extensions are never trusted for the decision.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

HEAD_BYTES = 64 * 1024
WIN_THRESHOLD = 0.5
_MAX_SAMPLE_LINES = 200
_MAX_SAMPLE_LINE_CHARS = 4096
_MIN_LINE_FRACTION = 0.6


@dataclass(frozen=True)
class Candidate:
    format_id: str
    score: float
    reason: str


@dataclass(frozen=True)
class DetectionResult:
    format_id: str | None  # None: binary content no parser handles
    confidence: float | None
    encoding: str | None
    candidates: tuple[Candidate, ...]
    corrupt_evtx_suspected: bool = False

    @property
    def is_generic(self) -> bool:
        return self.format_id in ("generic_text", "generic_jsonl")

    def candidates_json(self) -> list[dict[str, object]]:
        return [asdict(c) for c in self.candidates]


@dataclass(frozen=True)
class _Sample:
    text: str
    lines: tuple[str, ...]


def decode_head(head: bytes) -> tuple[str | None, str | None]:
    """Return (text, encoding) or (None, None) for binary content."""
    if head.startswith(b"\xef\xbb\xbf"):
        return head[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if head.startswith(b"\xff\xfe"):
        return head[2:].decode("utf-16-le", errors="replace"), "utf-16-le"
    if head.startswith(b"\xfe\xff"):
        return head[2:].decode("utf-16-be", errors="replace"), "utf-16-be"
    sample = head[:4096]
    if sample and sample.count(b"\x00") > len(sample) // 4:
        # UTF-16 without BOM: ASCII text has NUL in every other byte.
        odd_nuls = sample[1::2].count(b"\x00")
        if odd_nuls > len(sample) // 2 * 0.9:
            return head.decode("utf-16-le", errors="replace"), "utf-16-le"
        return None, None
    if b"\x00" in sample:
        return None, None
    return head.decode("utf-8", errors="replace"), "utf-8"


def _sample(text: str, truncated: bool) -> _Sample:
    lines = text.splitlines()
    if truncated and lines:
        lines = lines[:-1]  # the last line was probably cut by the 64 KiB window
    kept = tuple(line[:_MAX_SAMPLE_LINE_CHARS] for line in lines if line.strip())[
        :_MAX_SAMPLE_LINES
    ]
    return _Sample(text=text, lines=kept)


def _fraction(lines: tuple[str, ...], pattern: re.Pattern[str], *, search: bool = False) -> float:
    if not lines:
        return 0.0
    test = pattern.search if search else pattern.match
    return sum(1 for line in lines if test(line)) / len(lines)


def _line_detector(
    format_id: str, pattern: str, weight: float, label: str, *, search: bool = False
) -> Callable[[_Sample], Candidate | None]:
    compiled = re.compile(pattern)

    def detect(sample: _Sample) -> Candidate | None:
        fraction = _fraction(sample.lines, compiled, search=search)
        if fraction < _MIN_LINE_FRACTION:
            return None
        return Candidate(
            format_id,
            round(fraction * weight, 3),
            f"{fraction:.0%} of sampled lines match the {label} pattern",
        )

    return detect


_SYSLOG_BSD = r"(?:<\d{1,3}>)?[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ \S"
_SYSLOG_ISO = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}) \S+ \S"

_LINE_DETECTORS = (
    # Weights encode specificity: CEF/LEEF lines usually also match syslog, and must win.
    _line_detector("linux_syslog", rf"^(?:{_SYSLOG_BSD}|{_SYSLOG_ISO})", 0.9, "syslog"),
    _line_detector(
        "syslog_rfc5424",
        r"^<\d{1,3}>1 (?:\d{4}-\d{2}-\d{2}T\S+|-) \S+ \S+ \S+ \S+ ",
        0.95,
        "RFC 5424",
    ),
    _line_detector(
        "auditd", r"^(?:node=\S+ )?type=[A-Z_]+ msg=audit\(\d+\.\d+:\d+\):", 0.97, "auditd"
    ),
    _line_detector(
        "web_access",
        r'^(?:\S+ )?\S+ \S+ \S+ \[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "',
        0.95,
        "Apache/Nginx access log",
    ),
    _line_detector(
        "squid", r"^\d{9,10}\.\d{3}\s+-?\d+ \S+ [A-Z_]+/\d{3} \d+ \S+ \S+", 0.95, "Squid"
    ),
    _line_detector("cef", r"CEF:\d+\|", 0.97, "CEF", search=True),
    _line_detector("leef", r"LEEF:\d(?:\.\d)?\|", 0.97, "LEEF", search=True),
)


def _json_objects(lines: tuple[str, ...], limit: int = 50) -> tuple[list[dict[str, object]], int]:
    objects: list[dict[str, object]] = []
    checked = 0
    for line in lines[:limit]:
        checked += 1
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            objects.append(value)
    return objects, checked


def _detect_json(sample: _Sample) -> list[Candidate]:
    candidates: list[Candidate] = []
    objects, checked = _json_objects(sample.lines)
    if checked and len(objects) / checked >= 0.9:
        journald = sum(1 for o in objects if "__REALTIME_TIMESTAMP" in o and "MESSAGE" in o)
        if journald / len(objects) >= _MIN_LINE_FRACTION:
            candidates.append(
                Candidate(
                    "journald_json",
                    round(0.97 * journald / len(objects), 3),
                    "JSON lines with __REALTIME_TIMESTAMP and MESSAGE",
                )
            )
        zeek = sum(1 for o in objects if "ts" in o and ("uid" in o or "id.orig_h" in o))
        if zeek / len(objects) >= _MIN_LINE_FRACTION:
            candidates.append(
                Candidate(
                    "zeek_json",
                    round(0.9 * zeek / len(objects), 3),
                    "JSON lines with Zeek ts/uid/id.orig_h fields",
                )
            )
        candidates.append(
            Candidate("generic_jsonl", 0.3, f"{len(objects)}/{checked} sampled lines are JSON")
        )
    head = sample.text[:HEAD_BYTES]
    # Get-WinEvent | ConvertTo-Json, or evtx_dump JSON output.
    if '"TimeCreated"' in head and ('"ProviderName"' in head or '"LogName"' in head):
        candidates.append(
            Candidate("windows_evtx_json", 0.85, "JSON with TimeCreated and ProviderName/LogName")
        )
    elif '"EventID"' in head and '"System"' in head and '"Event"' in head:
        candidates.append(
            Candidate("windows_evtx_json", 0.85, "JSON with Event/System/EventID structure")
        )
    return candidates


def _detect_text_markers(sample: _Sample) -> list[Candidate]:
    candidates: list[Candidate] = []
    text = sample.text
    if text.startswith("#separator") and "\n#fields\t" in text:
        path = re.search(r"^#path\t(\S+)", text, re.MULTILINE)
        log_kind = path.group(1) if path else "unknown"
        candidates.append(
            Candidate("zeek_tsv", 0.98, f"Zeek TSV header (#separator, #fields), path={log_kind}")
        )
    if "http://schemas.microsoft.com/win/2004/08/events/event" in text[:8192]:
        candidates.append(Candidate("windows_evtx_xml", 0.97, "Windows event XML namespace"))
    first_line = sample.lines[0] if sample.lines else ""
    if first_line.startswith("Level,Date and Time,Source,Event ID,Task Category"):
        candidates.append(Candidate("windows_evtx_csv", 0.97, "Event Viewer CSV header row"))
    return candidates


def detect_format(head: bytes, filename: str) -> DetectionResult:
    if head.startswith(b"ElfFile\x00"):
        return DetectionResult(
            "windows_evtx", 1.0, None, (Candidate("windows_evtx", 1.0, "EVTX file signature"),)
        )

    corrupt_evtx = filename.lower().endswith(".evtx")
    text, encoding = decode_head(head)
    if text is None:
        return DetectionResult(None, None, None, (), corrupt_evtx_suspected=corrupt_evtx)

    sample = _sample(text, truncated=len(head) >= HEAD_BYTES)
    candidates: list[Candidate] = []
    for detector in _LINE_DETECTORS:
        found = detector(sample)
        if found is not None:
            candidates.append(found)
    candidates.extend(_detect_json(sample))
    candidates.extend(_detect_text_markers(sample))
    candidates.sort(key=lambda c: (-c.score, c.format_id))

    best = candidates[0] if candidates else None
    if best is not None and best.score >= WIN_THRESHOLD:
        return DetectionResult(
            best.format_id, best.score, encoding, tuple(candidates), corrupt_evtx_suspected=False
        )
    fallback = (
        "generic_jsonl"
        if any(c.format_id == "generic_jsonl" for c in candidates)
        else ("generic_text")
    )
    return DetectionResult(
        fallback, None, encoding, tuple(candidates), corrupt_evtx_suspected=corrupt_evtx
    )
