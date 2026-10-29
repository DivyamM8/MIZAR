"""Render docs/event-schema.md from the JSON Schema: python -m mizar.events.schema_docs"""

from __future__ import annotations

import sys
from typing import Any

from mizar.events.schema import event_json_schema


def _type(spec: dict[str, Any]) -> str:
    if "enum" in spec:
        values = [v for v in spec["enum"] if v is not None]
        nullable = None in spec["enum"]
        text = "enum: " + ", ".join(f"`{v}`" for v in values)
        return text + (" (nullable)" if nullable else "")
    if "const" in spec:
        return f"constant `{spec['const']}`"
    kind = spec.get("type", "object")
    if isinstance(kind, list):
        nullable = "null" in kind
        kind = " / ".join(k for k in kind if k != "null") + (" (nullable)" if nullable else "")
    if "format" in spec:
        kind += f", {spec['format']}"
    return str(kind)


def render() -> str:
    schema = event_json_schema()
    lines = [
        "# Normalized event schema",
        "",
        f"Version **{schema['x-schema-version']}**. Generated from "
        "`backend/mizar/schemas/event.v1.json` by `python -m mizar.events.schema_docs`; "
        "do not edit by hand.",
        "",
        schema["description"],
        "",
        "| Field | Type | Description |",
        "|---|---|---|",
    ]
    for name in schema["required"]:
        spec = schema["properties"][name]
        description = spec.get("description", "").replace("|", "\\|")
        lines.append(f"| `{name}` | {_type(spec)} | {description} |")
    lines += [
        "",
        "Every field is always present; fields a source does not provide are `null`.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.stdout.write(render())
