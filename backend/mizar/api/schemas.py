"""Request and response models for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mizar.core.timeutil import validate_timezone_name


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _check_timezone(value: str | None) -> str | None:
    return None if value is None else validate_timezone_name(value)


class CaseCreate(_Input):
    name: str = Field(min_length=1, max_length=200)
    analyst_name: str = Field(min_length=1, max_length=200)
    reference: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    default_timezone_hint: str | None = Field(default=None, max_length=64)

    _tz = field_validator("default_timezone_hint")(_check_timezone)


class CaseUpdate(_Input):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    analyst_name: str | None = Field(default=None, min_length=1, max_length=200)
    reference: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    default_timezone_hint: str | None = Field(default=None, max_length=64)

    _tz = field_validator("default_timezone_hint")(_check_timezone)

    @field_validator("name", "analyst_name")
    @classmethod
    def _required_not_null(cls, value: str | None) -> str:
        # Runs only when the field is sent; omitting it leaves the value unchanged.
        if value is None:
            raise ValueError("cannot be null")
        return value


class CaseDelete(_Input):
    confirm_name: str = Field(min_length=1, max_length=200)


class CaseOut(BaseModel):
    case_id: str
    name: str
    analyst_name: str
    reference: str | None
    description: str | None
    default_timezone_hint: str | None
    file_count: int
    created_at: datetime
    updated_at: datetime


class CaseDeleted(BaseModel):
    case_id: str
    deleted: bool
    source_files_deleted: int
    blobs_deleted: int
    blobs_retained_shared: int
    blob_errors: list[dict[str, Any]]


class ValidationMessage(BaseModel):
    level: str
    code: str
    message: str
    details: dict[str, Any]


class SourceFileOut(BaseModel):
    source_file_id: str
    case_id: str
    sequence: int
    parent_file_id: str | None
    archive_member_path: str | None
    archive_depth: int
    sha256: str
    original_filename: str
    size_bytes: int
    uploaded_by: str
    ingestion_time: datetime
    container_type: str | None
    detected_format: str | None
    detection_confidence: float | None
    detection_candidates: list[dict[str, Any]] | None
    encoding: str | None
    format_override: str | None
    effective_format: str | None
    timezone_hint: str | None
    year_hint: int | None
    status: str
    integrity_status: str
    last_verified_at: datetime | None
    validation_messages: list[ValidationMessage]

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> SourceFileOut:
        return cls(
            **{k: v for k, v in row.items() if k != "blob_sha256"},
            sha256=row["blob_sha256"],
            effective_format=row["format_override"] or row["detected_format"],
        )


class JobOut(BaseModel):
    job_id: str
    case_id: str | None
    job_type: str
    status: str
    progress: float
    progress_message: str | None
    result: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    attempts: int
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class UploadOut(BaseModel):
    source_file: SourceFileOut
    job_id: str


class JobQueued(BaseModel):
    job_id: str


class FormatOut(BaseModel):
    format_id: str
    label: str
    family: str


class ParseResultOut(BaseModel):
    parse_result_id: str
    format_id: str
    parser_name: str
    parser_version: str
    timezone_hint: str | None
    year_hint: int | None
    status: str
    started_at: datetime
    finished_at: datetime | None
    records_total: int
    records_parsed: int
    records_partial: int
    records_unparsed: int
    warnings_by_code: dict[str, int]
    file_problems: dict[str, Any]
    first_timestamp_utc: datetime | None
    last_timestamp_utc: datetime | None
    error_code: str | None
    error_message: str | None


class SourceFileWithParse(SourceFileOut):
    parse: ParseResultOut | None


class Reparse(_Input):
    format_override: str | None = Field(default=None, max_length=40)
    timezone_hint: str | None = Field(default=None, max_length=64)
    year_hint: int | None = Field(default=None, ge=1970, le=2100)

    _tz = field_validator("timezone_hint")(_check_timezone)


class EventOut(BaseModel):
    event_id: str
    schema_version: str
    case_id: str
    source_file_id: str
    parse_result_id: str
    source_type: str
    parser_name: str
    parser_version: str
    record_index: int
    original_record_reference: dict[str, Any]
    record_hash: str
    timestamp_original: str | None
    timestamp_utc: datetime | None
    timestamp_precision: str | None
    timezone_assumption: str
    hostname: str | None
    username: str | None
    user_domain: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    event_category: str | None
    event_type: str | None
    event_outcome: str | None
    event_code: str | None
    process_name: str | None
    process_id: int | None
    session_id: str | None
    message: str | None
    extra: dict[str, Any]
    parsing_status: str
    parse_warnings: list[str]
    ingestion_time: datetime


class RawRecordOut(BaseModel):
    # evidence_file: read back from the original by locator; stored_copy: kept at parse time.
    source: str
    encoding: str
    size_bytes: int
    text: str
    lossless: bool
    # For evidence_file reads: whether the bytes still match record_hash.
    verified: bool | None
    display_truncated: bool


class EventGroupOut(BaseModel):
    group_id: str
    group_type: str
    member_count: int
    members: list[dict[str, str]]


class EventDetail(EventOut):
    raw_record: RawRecordOut | None
    groups: list[EventGroupOut]


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    limit: int
    offset: int
