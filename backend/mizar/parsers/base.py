"""Parser contract (DESIGN.md §7.1).

A parser has two halves:
- records() frames the file into RecordUnits (exact raw bytes + locator). It
  owns file-level state (headers, multi-line grouping) and may yield
  FileProblems for non-fatal damage such as unreadable EVTX chunks.
- normalize() maps one RecordUnit to schema fields. The pipeline calls it per
  record inside a try/except, so a bug or odd record never aborts the file.

A new parser instance is created for every file, so both halves may keep
per-file state (normalize is called in record order).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, ClassVar


@dataclass(frozen=True)
class ParseContext:
    case_id: str
    source_file_id: str
    sha256: str
    filename: str
    blob_path: Path
    encoding: str | None
    timezone_hint: str | None
    year_hint: int | None


@dataclass(frozen=True)
class Timestamp:
    original: str | None
    utc: datetime | None
    precision: str | None
    assumption: str
    warnings: tuple[str, ...] = ()


NO_TIMESTAMP = Timestamp(None, None, None, "none")


@dataclass
class RecordUnit:
    raw: bytes
    raw_encoding: str
    locator: dict[str, Any]
    payload: Any = None
    # Set when raw was capped (overlong line): hash and length of the full record.
    full_hash: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FileProblem:
    code: str
    message: str
    details: dict[str, Any]


@dataclass
class Normalized:
    fields: dict[str, Any]
    timestamp: Timestamp
    status: str = "parsed"
    warnings: list[str] = field(default_factory=list)
    source_type: str | None = None
    parser_name: str | None = None


class FileParseError(Exception):
    """The file cannot be read any further. Records already produced are kept."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Parser(ABC):
    format_id: ClassVar[str]
    name: ClassVar[str]
    version: ClassVar[str]
    source_type: ClassVar[str]

    def __init__(self, ctx: ParseContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def records(self, stream: BinaryIO) -> Iterator[RecordUnit | FileProblem]: ...

    @abstractmethod
    def normalize(self, unit: RecordUnit) -> Normalized: ...


REGISTRY: dict[str, type[Parser]] = {}


def register(parser: type[Parser]) -> type[Parser]:
    if parser.format_id in REGISTRY:
        raise ValueError(f"duplicate parser for {parser.format_id}")
    REGISTRY[parser.format_id] = parser
    return parser


def none_if_dash(value: Any) -> Any:
    """Common 'no value' markers in logs become None."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip() in ("", "-", "(null)"):
        return None
    return value
