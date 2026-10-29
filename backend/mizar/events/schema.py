"""Normalized event schema v1 (DESIGN.md §5). The JSON Schema file is the source of truth."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any

from mizar.versions import EVENT_SCHEMA_VERSION

SCHEMA_RESOURCE = "event.v1.json"


@cache
def event_json_schema() -> dict[str, Any]:
    text = files("mizar.schemas").joinpath(SCHEMA_RESOURCE).read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    if schema["x-schema-version"] != EVENT_SCHEMA_VERSION:
        raise RuntimeError("event schema file and EVENT_SCHEMA_VERSION disagree")
    return schema


def _enum(field: str) -> frozenset[str]:
    values = event_json_schema()["properties"][field]["enum"]
    return frozenset(v for v in values if v is not None)


SOURCE_TYPES = _enum("source_type")
EVENT_CATEGORIES = _enum("event_category")
EVENT_OUTCOMES = _enum("event_outcome")
PARSING_STATUSES = _enum("parsing_status")
TIMESTAMP_PRECISIONS = _enum("timestamp_precision")
FIELDS: tuple[str, ...] = tuple(event_json_schema()["required"])
