"""Evidence upload and source-file endpoints.

Uploads are one file per request with the raw bytes as the body, streamed
straight into the evidence store while hashing (no multipart buffering to a
temp directory). Clients upload several files with several requests.
"""

from __future__ import annotations

from typing import Annotated

import anyio.to_thread
from fastapi import APIRouter, Query, Request, status
from starlette.requests import ClientDisconnect

from mizar.api.deps import EngineDep, SettingsDep, StoreDep
from mizar.api.schemas import FormatOut, JobQueued, SourceFileOut, UploadOut
from mizar.core.errors import ErrorCode, MizarError
from mizar.core.timeutil import validate_timezone_name
from mizar.evidence import service as evidence
from mizar.evidence.store import CHUNK_BYTES, BlobWriter
from mizar.ingest.formats import FORMATS, is_known_format

router = APIRouter(tags=["evidence"])


def _invalid(field: str, message: str) -> MizarError:
    return MizarError(
        ErrorCode.VALIDATION_ERROR,
        "The request is invalid.",
        details={"errors": [{"loc": ["query", field], "msg": message, "type": "value_error"}]},
    )


@router.get("/api/formats")
def list_formats() -> list[FormatOut]:
    return [
        FormatOut(format_id=f.format_id, label=f.label, family=f.family) for f in FORMATS.values()
    ]


@router.post("/api/cases/{case_id}/files", status_code=status.HTTP_201_CREATED)
async def upload_file(
    case_id: str,
    request: Request,
    engine: EngineDep,
    store: StoreDep,
    settings: SettingsDep,
    filename: Annotated[str, Query(min_length=1, max_length=1024)],
    timezone_hint: Annotated[str | None, Query(max_length=64)] = None,
    year_hint: Annotated[int | None, Query(ge=1970, le=2100)] = None,
    format_override: Annotated[str | None, Query(max_length=40)] = None,
) -> UploadOut:
    if "\x00" in filename:
        raise _invalid("filename", "must not contain NUL")
    if timezone_hint is not None:
        try:
            validate_timezone_name(timezone_hint)
        except ValueError as exc:
            raise _invalid("timezone_hint", str(exc)) from exc
    if format_override is not None and not is_known_format(format_override):
        raise _invalid("format_override", f"unknown format {format_override!r}")

    def check_case_and_budget() -> int:
        with engine.connect() as conn:
            evidence.require_case(conn, case_id)
            used = evidence.case_bytes_used(conn, case_id)
        return settings.max_case_uncompressed_bytes - used

    budget_remaining = await anyio.to_thread.run_sync(check_case_and_budget)
    limit = max(min(settings.max_file_bytes, budget_remaining), 0)

    def limit_error(max_bytes: int) -> MizarError:
        if max_bytes >= settings.max_file_bytes:
            return MizarError(
                ErrorCode.FILE_TOO_LARGE,
                "The file exceeds the per-file size limit.",
                details={"limit_bytes": settings.max_file_bytes},
            )
        return MizarError(
            ErrorCode.CASE_BUDGET_EXCEEDED,
            "The file exceeds the case's remaining storage budget.",
            details={"remaining_bytes": max(budget_remaining, 0)},
        )

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise limit_error(limit)

    writer: BlobWriter = await anyio.to_thread.run_sync(store.writer, limit, limit_error)
    try:
        buffer = bytearray()
        async for chunk in request.stream():
            buffer += chunk
            if len(buffer) >= CHUNK_BYTES:
                await anyio.to_thread.run_sync(writer.write, bytes(buffer))
                buffer.clear()
        if buffer:
            await anyio.to_thread.run_sync(writer.write, bytes(buffer))
        row, job_id = await anyio.to_thread.run_sync(
            lambda: evidence.register_upload(
                engine,
                writer,
                case_id=case_id,
                original_filename=filename,
                timezone_hint=timezone_hint,
                year_hint=year_hint,
                format_override=format_override,
            )
        )
    except ClientDisconnect as exc:
        writer.abort()
        raise MizarError(
            ErrorCode.UPLOAD_INCOMPLETE, "The upload was interrupted; nothing was stored."
        ) from exc
    except BaseException:
        writer.abort()
        raise
    return UploadOut(source_file=SourceFileOut.from_row(row), job_id=job_id)


@router.get("/api/cases/{case_id}/files")
def list_files(case_id: str, engine: EngineDep) -> list[SourceFileOut]:
    return [SourceFileOut.from_row(row) for row in evidence.list_source_files(engine, case_id)]


@router.get("/api/cases/{case_id}/files/{source_file_id}")
def get_file(case_id: str, source_file_id: str, engine: EngineDep) -> SourceFileOut:
    return SourceFileOut.from_row(evidence.get_source_file(engine, case_id, source_file_id))


@router.post("/api/cases/{case_id}/verify", status_code=status.HTTP_202_ACCEPTED)
def verify_case(case_id: str, engine: EngineDep) -> JobQueued:
    return JobQueued(job_id=evidence.queue_verification(engine, case_id))
