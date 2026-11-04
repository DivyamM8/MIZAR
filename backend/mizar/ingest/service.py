"""Ingest job: expand archives, then detect the format of every leaf file.

Idempotent: if the job is retried after a crash, members created by the
earlier attempt are deleted and re-created (their blobs are content-addressed,
so nothing is lost or duplicated).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import Engine, delete, select

from mizar.core.errors import ErrorCode, MizarError
from mizar.db.tables import source_files
from mizar.evidence import service as evidence
from mizar.evidence.archives import (
    ArchiveLimits,
    ByteBudget,
    ContainerType,
    ExtractedMember,
    detect_container,
    detect_unsupported_archive,
    expand,
)
from mizar.evidence.store import StoredBlob
from mizar.ingest.detect import HEAD_BYTES, detect_format
from mizar.ingest.formats import is_known_format
from mizar.ingest.parse import queue_parse
from mizar.jobs.worker import JobCancelled, JobContext, WorkerStopping

log = logging.getLogger(__name__)


def abort_ingest(engine: Engine, job: dict[str, Any], message: str) -> None:
    """A timed-out ingest: files of this upload not yet processed are marked failed."""
    failure = evidence.message("error", ErrorCode.JOB_TIMEOUT, message)
    with engine.begin() as conn:
        pending = [job["payload"]["source_file_id"]]
        while pending:
            file_id = pending.pop()
            row = evidence.get_source_file_conn(conn, file_id)
            if row["status"] in ("stored", "expanding"):
                evidence.update_source_file(
                    conn,
                    file_id,
                    status="failed",
                    validation_messages=[*row["validation_messages"], failure],
                )
            pending.extend(
                conn.execute(
                    select(source_files.c.source_file_id).where(
                        source_files.c.parent_file_id == file_id
                    )
                ).scalars()
            )


def ingest_file_job(ctx: JobContext) -> dict[str, Any]:
    root_id: str = ctx.payload["source_file_id"]
    pending = [root_id]
    processed = 0
    statuses: dict[str, int] = {}

    while pending:
        ctx.progress(processed / (processed + len(pending)), f"Processed {processed} file(s)")
        file_id = pending.pop()
        try:
            status, children = _process_one(ctx, file_id)
        except (JobCancelled, WorkerStopping):
            raise
        except Exception as exc:
            # Record the failure on the file, then let the worker log and fail the job.
            _record_failure(ctx, file_id, exc)
            raise
        statuses[status] = statuses.get(status, 0) + 1
        pending.extend(reversed(children))
        processed += 1

    return {"root_source_file_id": root_id, "files_processed": processed, "statuses": statuses}


def _process_one(ctx: JobContext, file_id: str) -> tuple[str, list[str]]:
    deps = ctx.deps
    with deps.engine.connect() as conn:
        row = evidence.get_source_file_conn(conn, file_id)
    head = deps.store.read_head(row["blob_sha256"], HEAD_BYTES)
    messages: list[dict[str, Any]] = list(row["validation_messages"])

    container = detect_container(head)
    if container is not None:
        return _process_container(ctx, row, container, messages)

    unsupported = detect_unsupported_archive(head)
    if unsupported is not None:
        messages.append(
            evidence.message(
                "warning",
                ErrorCode.UNSUPPORTED_ARCHIVE,
                f"{unsupported} archives are not expanded; the file is kept as evidence.",
                {"archive_type": unsupported},
            )
        )
        _save(ctx, file_id, status="unsupported", validation_messages=messages)
        return "unsupported", []

    result = detect_format(head, row["original_filename"])
    if result.format_id is None:
        if result.corrupt_evtx_suspected:
            messages.append(
                evidence.message(
                    "error",
                    ErrorCode.EVTX_CORRUPT_HEADER,
                    "The file is named .evtx but lacks the EVTX signature; it may be corrupt.",
                )
            )
        messages.append(
            evidence.message(
                "warning",
                ErrorCode.UNSUPPORTED_BINARY,
                "Binary content in no supported format; the file is kept as evidence.",
            )
        )
        _save(
            ctx,
            file_id,
            status="unsupported",
            detection_candidates=[],
            validation_messages=messages,
        )
        return "unsupported", []

    if result.is_generic:
        messages.append(
            evidence.message(
                "warning",
                ErrorCode.FORMAT_UNDETECTED,
                "No specific format recognized; the generic parser will be used "
                "(reported as a coverage gap).",
            )
        )
    override = row["format_override"]
    if override is not None and not is_known_format(override):
        raise MizarError(ErrorCode.VALIDATION_ERROR, f"Unknown format override {override!r}.")
    with ctx.deps.engine.begin() as conn:
        evidence.update_source_file(
            conn,
            file_id,
            status="ready",
            detected_format=result.format_id,
            detection_confidence=result.confidence,
            detection_candidates=result.candidates_json(),
            encoding=result.encoding,
            validation_messages=messages,
        )
        queue_parse(conn, row["case_id"], file_id)
    return "ready", []


def _process_container(
    ctx: JobContext,
    row: dict[str, Any],
    container: ContainerType,
    messages: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    deps = ctx.deps
    settings = deps.settings
    file_id = row["source_file_id"]

    if row["format_override"] is not None:
        messages.append(
            evidence.message(
                "warning",
                ErrorCode.FORMAT_OVERRIDE_IGNORED,
                "A format override does not apply to an archive; its members are detected "
                "individually.",
            )
        )
    if row["archive_depth"] >= settings.max_archive_depth:
        messages.append(
            evidence.message(
                "warning",
                ErrorCode.ARCHIVE_DEPTH_LIMIT,
                "Archive nesting limit reached; this archive was kept but not expanded.",
                {"max_depth": settings.max_archive_depth},
            )
        )
        _save(
            ctx,
            file_id,
            status="unsupported",
            container_type=container.value,
            validation_messages=messages,
        )
        return "unsupported", []

    with deps.engine.begin() as conn:
        # Retry safety: drop members from an earlier, interrupted attempt.
        conn.execute(delete(source_files).where(source_files.c.parent_file_id == file_id))
        evidence.update_source_file(
            conn, file_id, status="expanding", container_type=container.value
        )
        used = evidence.case_bytes_used(conn, row["case_id"], exclude_file_id=file_id)

    limits = ArchiveLimits(
        max_members=settings.max_archive_members,
        max_member_bytes=settings.max_file_bytes,
        max_compression_ratio=settings.max_compression_ratio,
        ratio_floor_bytes=settings.compression_ratio_floor_bytes,
    )
    budget = ByteBudget(remaining=max(settings.max_case_uncompressed_bytes - used, 0))
    children: list[str] = []
    problems = 0
    try:
        for item in expand(
            deps.store,
            container,
            row["blob_sha256"],
            row["original_filename"],
            archive_size=row["size_bytes"],
            limits=limits,
            budget=budget,
            register=lambda path, blob, warnings: _add_member(ctx, row, path, blob, warnings),
        ):
            ctx.check_cancelled()
            if isinstance(item, ExtractedMember):
                children.append(item.source_file_id)
            else:
                problems += 1
                messages.append(evidence.message("warning", item.code, item.message, item.details))
    except MizarError as exc:
        if exc.code not in (ErrorCode.ARCHIVE_CORRUPT, ErrorCode.EVIDENCE_MISSING):
            raise
        messages.append(evidence.message("error", exc.code, exc.message, exc.details))
        _save(ctx, file_id, status="failed", validation_messages=messages)
        return "failed", children

    _save(ctx, file_id, status="expanded", validation_messages=messages)
    log.info(
        "archive expanded: %d member(s), %d problem(s)",
        len(children),
        problems,
        extra={"job_id": ctx.job_id, "case_id": row["case_id"]},
    )
    return "expanded", children


def _add_member(
    ctx: JobContext,
    parent: dict[str, Any],
    member_path: str,
    blob: StoredBlob,
    warnings: list[dict[str, Any]],
) -> str:
    with ctx.deps.engine.begin() as conn:
        child = evidence.insert_source_file(
            conn,
            case_id=parent["case_id"],
            blob=blob,
            original_filename=member_path.rsplit("/", 1)[-1],
            uploaded_by=parent["uploaded_by"],
            parent_file_id=parent["source_file_id"],
            archive_member_path=member_path,
            archive_depth=parent["archive_depth"] + 1,
            timezone_hint=parent["timezone_hint"],
            year_hint=parent["year_hint"],
            messages=warnings,
        )
    return str(child["source_file_id"])


def _save(ctx: JobContext, file_id: str, **values: Any) -> None:
    with ctx.deps.engine.begin() as conn:
        evidence.update_source_file(conn, file_id, **values)


def _record_failure(ctx: JobContext, file_id: str, exc: Exception) -> None:
    if isinstance(exc, MizarError):
        failure = evidence.message("error", exc.code, exc.message, exc.details)
    else:
        failure = evidence.message(
            "error",
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error while ingesting. See the application log for job {ctx.job_id}.",
        )
    with ctx.deps.engine.begin() as conn:
        row = evidence.get_source_file_conn(conn, file_id)
        evidence.update_source_file(
            conn,
            file_id,
            status="failed",
            validation_messages=[*row["validation_messages"], failure],
        )
