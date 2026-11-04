"""Identifier generation (DESIGN.md §3.1).

Random IDs use ULIDs (time-sortable). Event IDs are UUIDv5 so the same record
in the same file in the same case always gets the same ID.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any

from ulid import ULID

# Fixed forever: changing it would change every event ID.
MIZAR_EVENT_NAMESPACE = uuid.UUID("371b0265-6ade-4aff-b046-33a15e05bb03")


def new_case_id() -> str:
    return f"CASE-{ULID()}"


def new_run_id() -> str:
    return f"RUN-{ULID()}"


def new_export_id() -> str:
    return f"EXP-{ULID()}"


def new_job_id() -> str:
    return f"JOB-{ULID()}"


def new_request_id() -> str:
    return f"req_{ULID()}"


def new_parse_result_id() -> str:
    return f"PR-{ULID()}"


def new_source_file_id() -> str:
    return f"SF-{ULID()}"


def canonical_locator(locator: Mapping[str, Any]) -> str:
    """Stable text form of an original_record_reference."""
    return json.dumps(locator, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event_id(
    case_id: str, source_file_id: str, source_sha256: str, locator: Mapping[str, Any]
) -> str:
    """Stable per record: re-parsing the same source file yields the same IDs.

    source_file_id is included because one case can hold the same content twice
    (a duplicate upload); those are distinct records, linked by duplicate groups.
    """
    return event_id_from_canonical(
        case_id, source_file_id, source_sha256, canonical_locator(locator)
    )


def event_id_from_canonical(
    case_id: str, source_file_id: str, source_sha256: str, locator_json: str
) -> str:
    name = f"{case_id}|{source_file_id}|{source_sha256.lower()}|{locator_json}"
    return str(uuid.uuid5(MIZAR_EVENT_NAMESPACE, name))


def finding_id(run_id: str, sequence: int) -> str:
    if sequence < 1:
        raise ValueError("sequence starts at 1")
    return f"{run_id}-F{sequence:04d}"
