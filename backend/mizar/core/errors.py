"""Error taxonomy (DESIGN.md §14).

Every error that crosses a component boundary is a MizarError with a stable
code. Codes are part of the API contract: never rename one, only add new ones.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    # Request
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    HTTP_ERROR = "HTTP_ERROR"
    CASE_NOT_FOUND = "CASE_NOT_FOUND"
    CASE_BUSY = "CASE_BUSY"
    CASE_NAME_MISMATCH = "CASE_NAME_MISMATCH"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    FILE_NOT_PARSEABLE = "FILE_NOT_PARSEABLE"
    JOB_NOT_CANCELLABLE = "JOB_NOT_CANCELLABLE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    CASE_BUDGET_EXCEEDED = "CASE_BUDGET_EXCEEDED"
    UPLOAD_INCOMPLETE = "UPLOAD_INCOMPLETE"
    UNSUPPORTED_ARCHIVE = "UNSUPPORTED_ARCHIVE"
    # Local-access protection
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    ORIGIN_NOT_ALLOWED = "ORIGIN_NOT_ALLOWED"
    AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"  # noqa: S105 (error code)
    # Evidence
    EVIDENCE_INTEGRITY_MISMATCH = "EVIDENCE_INTEGRITY_MISMATCH"
    STORAGE_FULL = "STORAGE_FULL"
    HASH_IO_ERROR = "HASH_IO_ERROR"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    # File-level validation messages (warnings recorded on a source file)
    DUPLICATE_UPLOAD = "DUPLICATE_UPLOAD"
    EMPTY_FILE = "EMPTY_FILE"
    FORMAT_OVERRIDE_IGNORED = "FORMAT_OVERRIDE_IGNORED"
    UNSUPPORTED_BINARY = "UNSUPPORTED_BINARY"
    # Archive
    ARCHIVE_PATH_TRAVERSAL = "ARCHIVE_PATH_TRAVERSAL"
    ARCHIVE_BOMB_SUSPECTED = "ARCHIVE_BOMB_SUSPECTED"
    ARCHIVE_MEMBER_LIMIT = "ARCHIVE_MEMBER_LIMIT"
    ARCHIVE_ENCRYPTED = "ARCHIVE_ENCRYPTED"
    ARCHIVE_CORRUPT = "ARCHIVE_CORRUPT"
    ARCHIVE_TRUNCATED = "ARCHIVE_TRUNCATED"
    ARCHIVE_DEPTH_LIMIT = "ARCHIVE_DEPTH_LIMIT"
    ARCHIVE_MEMBER_UNSUPPORTED = "ARCHIVE_MEMBER_UNSUPPORTED"
    # Parsing (file level)
    FORMAT_UNDETECTED = "FORMAT_UNDETECTED"
    EVTX_CORRUPT_HEADER = "EVTX_CORRUPT_HEADER"
    ENCODING_UNSUPPORTED = "ENCODING_UNSUPPORTED"
    # Detection
    RULE_INVALID = "RULE_INVALID"
    RULE_RUNTIME_ERROR = "RULE_RUNTIME_ERROR"
    REGEX_TIMEOUT = "REGEX_TIMEOUT"
    # Jobs
    JOB_CRASHED = "JOB_CRASHED"
    JOB_CANCELLED = "JOB_CANCELLED"
    # Reporting
    REPORT_RENDER_FAILED = "REPORT_RENDER_FAILED"
    # Fallback
    INTERNAL_ERROR = "INTERNAL_ERROR"


_DEFAULT_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.METHOD_NOT_ALLOWED: 405,
    ErrorCode.HTTP_ERROR: 400,
    ErrorCode.CASE_NOT_FOUND: 404,
    ErrorCode.CASE_BUSY: 409,
    ErrorCode.CASE_NAME_MISMATCH: 422,
    ErrorCode.FILE_NOT_FOUND: 404,
    ErrorCode.JOB_NOT_FOUND: 404,
    ErrorCode.FILE_NOT_PARSEABLE: 409,
    ErrorCode.JOB_NOT_CANCELLABLE: 409,
    ErrorCode.FILE_TOO_LARGE: 413,
    ErrorCode.CASE_BUDGET_EXCEEDED: 413,
    ErrorCode.UPLOAD_INCOMPLETE: 400,
    ErrorCode.UNSUPPORTED_ARCHIVE: 415,
    ErrorCode.HOST_NOT_ALLOWED: 400,
    ErrorCode.ORIGIN_NOT_ALLOWED: 403,
    ErrorCode.AUTH_TOKEN_INVALID: 401,
    ErrorCode.EVIDENCE_INTEGRITY_MISMATCH: 409,
    ErrorCode.STORAGE_FULL: 507,
    ErrorCode.EVIDENCE_MISSING: 409,
    ErrorCode.ARCHIVE_PATH_TRAVERSAL: 422,
    ErrorCode.ARCHIVE_BOMB_SUSPECTED: 422,
    ErrorCode.ARCHIVE_MEMBER_LIMIT: 422,
    ErrorCode.ARCHIVE_ENCRYPTED: 422,
    ErrorCode.RULE_INVALID: 422,
}


def default_http_status(code: ErrorCode) -> int:
    return _DEFAULT_HTTP_STATUS.get(code, 500)


class MizarError(Exception):
    """An expected, classified failure with a stable error code."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details: dict[str, Any] = dict(details or {})
        self.http_status = http_status or default_http_status(code)

    def __repr__(self) -> str:
        return f"MizarError({self.code.value}, {self.message!r})"


def error_envelope(
    code: ErrorCode,
    message: str,
    request_id: str | None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The API error body (DESIGN.md §14.2)."""
    return {
        "error": {
            "code": code.value,
            "message": message,
            "details": dict(details or {}),
            "request_id": request_id,
        }
    }
