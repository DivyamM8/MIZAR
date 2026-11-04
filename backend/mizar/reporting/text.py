"""Making untrusted log text safe to place in a PDF or a spreadsheet (DESIGN.md §15)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

# ReportLab's built-in fonts encode text as WinAnsi (cp1252).
_PDF_ENCODING = "cp1252"
# Spreadsheet programs evaluate cells starting with these as formulas (§13.2).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def visible(value: str) -> str:
    """Replace characters the PDF fonts cannot draw with visible escapes.

    Control characters become \\xNN and characters outside cp1252 become \\u{NNNN},
    so nothing is dropped silently or drawn as an empty box; the exact text is in
    the JSON export.
    """
    out = []
    for char in value:
        code = ord(char)
        if char in "\n\t":
            out.append(char)
        elif code < 0x20 or 0x7F <= code < 0xA0:
            out.append(f"\\x{code:02x}")
        else:
            try:
                char.encode(_PDF_ENCODING)
            except UnicodeEncodeError:
                out.append(f"\\u{{{code:04x}}}")
            else:
                out.append(char)
    return "".join(out)


def clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f" [... {len(value) - limit} more characters]"


def para(value: Any, limit: int | None = None) -> str:
    """Untrusted text as ReportLab Paragraph markup: escaped, never interpreted."""
    text = "" if value is None else str(value)
    if limit is not None:
        text = clip(text, limit)
    return escape(visible(text)).replace("\n", "<br/>").replace("\t", "    ")


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
