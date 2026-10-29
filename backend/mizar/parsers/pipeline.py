"""Turns parser output into validated event rows (DESIGN.md §5.1 parser rules).

Validation never coerces: an invalid IP or port becomes null, the original
value is kept in extra, and a warning is added.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import zlib
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any

from mizar.core.ids import canonical_locator, event_id_from_canonical
from mizar.events.schema import EVENT_CATEGORIES, EVENT_OUTCOMES, PARSING_STATUSES
from mizar.parsers.base import (
    Normalized,
    ParseContext,
    Parser,
    RecordUnit,
    Timestamp,
)
from mizar.versions import EVENT_SCHEMA_VERSION

log = logging.getLogger(__name__)

_FIELDS = frozenset(
    {
        "hostname",
        "username",
        "user_domain",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "event_category",
        "event_type",
        "event_outcome",
        "event_code",
        "process_name",
        "process_id",
        "session_id",
        "message",
        "extra",
    }
)
# Warnings meaning "some field could not be extracted or validated".
DEGRADING_WARNINGS = frozenset(
    {
        "timestamp_unparsed",
        "dst_ambiguous",
        "dst_nonexistent",
        "invalid_ip",
        "invalid_port",
        "invalid_pid",
        "truncated_record",
        "encoding_replaced",
        "parser_exception",
        "event_data_positional",
        "event_data_unavailable",
        "field_unparsed",
    }
)


@dataclass
class EventRows:
    event: dict[str, Any]
    # A stored copy of the raw bytes, or None when the locator reads them back exactly.
    raw: dict[str, Any] | None
    # Canonical JSON of the locator (already computed for the event ID).
    locator_json: str


_SEEKABLE_KINDS = frozenset({"line", "lines", "json_line"})
_SEEKABLE_ENCODINGS = frozenset({"utf-8", "utf-8-sig"})
_COMPRESS_MIN_BYTES = 256


def _json_safe(value: Any, depth: int = 0) -> Any:
    if depth > 20:
        return str(value)
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): _json_safe(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_json_safe(v, depth + 1) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


_INVALID = object()


@lru_cache(maxsize=65536)
def _canonical_ip(text: str) -> object:
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return _INVALID


def _validate_ip(value: Any) -> str:
    result = _canonical_ip(str(value).strip())
    if result is _INVALID:
        raise ValueError("invalid IP address")
    return str(result)


def _validate_port(value: Any) -> int:
    port = int(str(value).strip())
    if not 0 <= port <= 65535:
        raise ValueError("port out of range")
    return port


def _validate_pid(value: Any) -> int:
    pid = int(str(value).strip())
    if pid < 0:
        raise ValueError("negative pid")
    return pid


_VALIDATORS = {
    "source_ip": (_validate_ip, "invalid_ip"),
    "destination_ip": (_validate_ip, "invalid_ip"),
    "source_port": (_validate_port, "invalid_port"),
    "destination_port": (_validate_port, "invalid_port"),
    "process_id": (_validate_pid, "invalid_pid"),
}
_CORE = tuple(sorted(_FIELDS - {"extra"}))


def clean_fields(fields: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Validate parser fields. Returns (fields, extra, warnings)."""
    extra = dict(fields.get("extra") or {})
    warnings: list[str] = []
    cleaned: dict[str, Any] = dict.fromkeys(_CORE)
    for name, value in fields.items():
        if name == "extra":
            continue
        if name not in cleaned:
            raise ValueError(f"parser produced unknown field {name!r}")
        if value is None:
            continue
        if isinstance(value, str) and value.strip() in ("", "-"):
            continue
        validator = _VALIDATORS.get(name)
        if validator is not None:
            validate, warning = validator
            try:
                value = validate(value)
            except (ValueError, TypeError):
                extra[f"{name}_raw"] = str(value)
                warnings.append(warning)
                continue
        elif not isinstance(value, str):
            value = str(value)
        cleaned[name] = value
    if cleaned["protocol"] is not None:
        cleaned["protocol"] = cleaned["protocol"].lower()
    if cleaned["event_category"] is not None and cleaned["event_category"] not in EVENT_CATEGORIES:
        raise ValueError(f"invalid event_category {cleaned['event_category']!r}")
    if cleaned["event_outcome"] is not None and cleaned["event_outcome"] not in EVENT_OUTCOMES:
        raise ValueError(f"invalid event_outcome {cleaned['event_outcome']!r}")
    return cleaned, extra, warnings


def raw_copy(unit: RecordUnit, event_id_value: str) -> dict[str, Any] | None:
    """Raw row to store, or None if the evidence file gives the bytes back exactly."""
    if unit.locator.get("kind") in _SEEKABLE_KINDS and unit.raw_encoding in _SEEKABLE_ENCODINGS:
        return None
    data, compression = unit.raw, "none"
    if len(data) >= _COMPRESS_MIN_BYTES:
        packed = zlib.compress(data, 6)
        if len(packed) < len(data):
            data, compression = packed, "zlib"
    return {
        "event_id": event_id_value,
        "encoding": unit.raw_encoding,
        "compression": compression,
        "size_bytes": len(unit.raw),
        "data": data,
    }


def _failed_normalization(unit: RecordUnit, exc: Exception) -> Normalized:
    text = unit.raw.decode("utf-8", errors="replace") if unit.raw_encoding != "binary" else None
    return Normalized(
        fields={"message": text, "extra": {"parser_error": type(exc).__name__}},
        timestamp=Timestamp(None, None, None, "none"),
        status="unparsed",
        warnings=["parser_exception"],
    )


def build_rows(
    parser: Parser,
    unit: RecordUnit,
    record_index: int,
    parse_result_id: str,
    ingestion_time: datetime,
) -> EventRows:
    ctx: ParseContext = parser.ctx
    try:
        normalized = parser.normalize(unit)
        fields, extra, validation_warnings = clean_fields(normalized.fields)
    except Exception as exc:  # one bad record must never abort the file
        log.warning(
            "parser %s failed on record %d: %s", parser.name, record_index, type(exc).__name__
        )
        normalized = _failed_normalization(unit, exc)
        fields, extra, validation_warnings = clean_fields(normalized.fields)

    warnings = list(
        dict.fromkeys(
            [
                *unit.warnings,
                *normalized.warnings,
                *normalized.timestamp.warnings,
                *validation_warnings,
            ]
        )
    )
    status = normalized.status
    if status not in PARSING_STATUSES:
        raise ValueError(f"invalid parsing status {status!r}")
    if status == "parsed" and DEGRADING_WARNINGS.intersection(warnings):
        status = "partial"

    stamp = normalized.timestamp
    record_hash = unit.full_hash or hashlib.sha256(unit.raw).hexdigest()
    locator_json = canonical_locator(unit.locator)
    identifier = event_id_from_canonical(ctx.case_id, ctx.source_file_id, ctx.sha256, locator_json)
    event = {
        "event_id": identifier,
        "schema_version": EVENT_SCHEMA_VERSION,
        "case_id": ctx.case_id,
        "source_file_id": ctx.source_file_id,
        "parse_result_id": parse_result_id,
        "source_type": normalized.source_type or parser.source_type,
        "parser_name": normalized.parser_name or parser.name,
        "parser_version": parser.version,
        "record_index": record_index,
        "original_record_reference": unit.locator,
        "record_hash": record_hash,
        "timestamp_original": stamp.original,
        "timestamp_utc": stamp.utc,
        "timestamp_precision": stamp.precision,
        "timezone_assumption": stamp.assumption,
        **fields,
        "extra": _json_safe(extra),
        "parsing_status": status,
        "parse_warnings": warnings,
        "ingestion_time": ingestion_time,
    }
    return EventRows(event, raw_copy(unit, identifier), locator_json)
