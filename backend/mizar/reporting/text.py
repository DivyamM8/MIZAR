"""Making untrusted log text safe to place in a PDF or a spreadsheet (DESIGN.md §15)."""

from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from mizar.reporting.fonts import FALLBACK_FONT, fallback_code_points

# ReportLab's built-in fonts encode text as WinAnsi (cp1252).
_PDF_ENCODING = "cp1252"
# Spreadsheet programs evaluate cells starting with these as formulas (§13.2).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
# Invisible or structural characters: always shown as escapes, because they can hide or
# reorder text (e.g. U+202E RIGHT-TO-LEFT OVERRIDE in a file name).
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# ReportLab draws text left to right without reordering; right-to-left scripts would read
# backwards, so they are escaped too.
_RTL = frozenset({"R", "AL", "AN"})

# (text, font): "base" (Helvetica, also used for escapes) or "fallback" (DejaVu Sans).
Piece = tuple[str, str]


def _kind(char: str) -> str:
    if char in "\n\t":
        return "base"
    if unicodedata.category(char) in _ESCAPED_CATEGORIES:
        return "escape"
    try:
        char.encode(_PDF_ENCODING)
    except UnicodeEncodeError:
        pass
    else:
        return "base"
    if unicodedata.bidirectional(char) in _RTL:
        return "escape"
    return "fallback" if ord(char) in fallback_code_points() else "escape"


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{{{code:04x}}}"


def pieces(value: str) -> list[Piece]:
    """Split text into runs for the base and the fallback font, with escapes applied."""
    out: list[Piece] = []
    for char in value:
        kind = _kind(char)
        text = _escape(char) if kind == "escape" else char
        group = "base" if kind == "escape" else kind
        if out and out[-1][1] == group:
            out[-1] = (out[-1][0] + text, group)
        else:
            out.append((text, group))
    return out


def visible(value: str) -> str:
    """The text as the PDF shows it: characters no font can draw (or that would hide
    or reorder text) become \\xNN or \\u{NNNN}. The exact text is in the JSON export."""
    return "".join(text for text, _ in pieces(value))


def clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f" [... {len(value) - limit} more characters]"


def para(value: Any, limit: int | None = None) -> str:
    """Untrusted text as ReportLab Paragraph markup: escaped, never interpreted."""
    text = "" if value is None else str(value)
    if limit is not None:
        text = clip(text, limit)
    markup = []
    for run, group in pieces(text):
        escaped = escape(run).replace("\n", "<br/>").replace("\t", "    ")
        markup.append(
            f'<font name="{FALLBACK_FONT}">{escaped}</font>' if group == "fallback" else escaped
        )
    return "".join(markup)


def utc(value: datetime | None) -> str:
    if value is None:
        return "no reliable time"
    return value.strftime("%Y-%m-%d %H:%M:%S") + (
        f".{value.microsecond // 1000:03d}Z" if value.microsecond else "Z"
    )


def size(value: int | None) -> str:
    if value is None:
        return "unknown"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if amount < 1024 or unit == "GiB":
            return f"{value} B" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def label(value: str) -> str:
    """false_positive -> False positive."""
    return value.replace("_", " ").capitalize()


def csv_cell(value: Any) -> Any:
    """A CSV value that a spreadsheet will show as text, never run as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list | tuple):
        value = "; ".join(str(v) for v in value)
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text
