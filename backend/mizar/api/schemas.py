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
