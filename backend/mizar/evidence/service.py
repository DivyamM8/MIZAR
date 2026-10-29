"""Source-file records and their link to stored blobs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import Connection, Engine, func, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import new_source_file_id
from mizar.core.timeutil import utc_now
from mizar.db.tables import cases, source_files
from mizar.evidence.store import BlobWriter, EvidenceStore, StoredBlob, VerifyStatus
from mizar.jobs import queue

INGEST_JOB = "ingest_file"
VERIFY_JOB = "verify_evidence"


def message(
    level: str, code: ErrorCode, text: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {"level": level, "code": code.value, "message": text, "details": details or {}}


def require_case(conn: Connection, case_id: str) -> dict[str, Any]:
    row = conn.execute(select(cases).where(cases.c.case_id == case_id)).mappings().first()
    if row is None:
        raise MizarError(ErrorCode.CASE_NOT_FOUND, "Case not found.", details={"case_id": case_id})
    return dict(row)


def case_bytes_used(conn: Connection, case_id: str, exclude_file_id: str | None = None) -> int:
    """Bytes of non-archive files in the case (the per-case uncompressed budget)."""
    query = select(func.coalesce(func.sum(source_files.c.size_bytes), 0)).where(
        source_files.c.case_id == case_id, source_files.c.container_type.is_(None)
    )
    if exclude_file_id is not None:
        query = query.where(source_files.c.source_file_id != exclude_file_id)
    return int(conn.execute(query).scalar_one())


def insert_source_file(
    conn: Connection,
    *,
    case_id: str,
    blob: StoredBlob,
    original_filename: str,
    uploaded_by: str,
    parent_file_id: str | None = None,
    archive_member_path: str | None = None,
    archive_depth: int = 0,
    timezone_hint: str | None = None,
    year_hint: int | None = None,
    format_override: str | None = None,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    all_messages = list(messages or [])
    duplicates = conn.execute(
        select(source_files.c.source_file_id, source_files.c.sequence).where(
            source_files.c.case_id == case_id, source_files.c.blob_sha256 == blob.sha256
        )
    ).all()
    if duplicates:
        all_messages.append(
            message(
                "warning",
                ErrorCode.DUPLICATE_UPLOAD,
                "Identical content is already in this case.",
                {"source_file_ids": [d.source_file_id for d in duplicates]},
            )
        )
    if blob.size_bytes == 0:
        all_messages.append(message("warning", ErrorCode.EMPTY_FILE, "The file is empty."))

    source_file_id = new_source_file_id()
    next_sequence = (
        select(func.coalesce(func.max(source_files.c.sequence), 0) + 1)
        .where(source_files.c.case_id == case_id)
        .scalar_subquery()
    )
    conn.execute(
        insert(source_files).values(
            source_file_id=source_file_id,
            case_id=case_id,
            sequence=next_sequence,
            parent_file_id=parent_file_id,
            archive_member_path=archive_member_path,
            archive_depth=archive_depth,
            blob_sha256=blob.sha256,
            original_filename=original_filename,
            size_bytes=blob.size_bytes,
            uploaded_by=uploaded_by,
            ingestion_time=utc_now(),
            format_override=format_override,
            timezone_hint=timezone_hint,
            year_hint=year_hint,
            status="stored",
            # The hash was computed while writing, so the stored copy is verified now.
            integrity_status="verified",
            last_verified_at=utc_now(),
            validation_messages=all_messages,
        )
    )
    return get_source_file_conn(conn, source_file_id)


def register_upload(
    engine: Engine,
    writer: BlobWriter,
    *,
    case_id: str,
    original_filename: str,
    timezone_hint: str | None,
    year_hint: int | None,
    format_override: str | None,
) -> tuple[dict[str, Any], str]:
    """Commit an uploaded blob, record it, and queue its ingest job.

    The record and the job are one transaction, committed under the store lock.
    """
    return writer.commit(
        lambda blob: _record_upload(
            engine,
            case_id=case_id,
            blob=blob,
            original_filename=original_filename,
            timezone_hint=timezone_hint,
            year_hint=year_hint,
            format_override=format_override,
        )
    )


def _record_upload(
    engine: Engine,
    *,
    case_id: str,
    blob: StoredBlob,
    original_filename: str,
    timezone_hint: str | None,
    year_hint: int | None,
    format_override: str | None,
) -> tuple[dict[str, Any], str]:
    with engine.begin() as conn:
        case = require_case(conn, case_id)
        row = insert_source_file(
            conn,
            case_id=case_id,
            blob=blob,
            original_filename=original_filename,
            uploaded_by=case["analyst_name"],
            timezone_hint=timezone_hint or case["default_timezone_hint"],
            year_hint=year_hint,
            format_override=format_override,
        )
        job_id = queue.enqueue(conn, INGEST_JOB, {"source_file_id": row["source_file_id"]}, case_id)
    return row, job_id


def blob_is_referenced(conn: Connection, sha256: str) -> bool:
    return (
        conn.execute(
            select(source_files.c.source_file_id)
            .where(source_files.c.blob_sha256 == sha256)
            .limit(1)
        ).first()
        is not None
    )


def release_blob_if_unreferenced(engine: Engine, store: EvidenceStore, sha256: str) -> bool:
    with store.lock():
        with engine.connect() as conn:
            if blob_is_referenced(conn, sha256):
                return False
        return store.delete(sha256)


def get_source_file_conn(conn: Connection, source_file_id: str) -> dict[str, Any]:
    row = (
        conn.execute(select(source_files).where(source_files.c.source_file_id == source_file_id))
        .mappings()
        .first()
    )
    if row is None:
        raise MizarError(
            ErrorCode.FILE_NOT_FOUND,
            "Source file not found.",
            details={"source_file_id": source_file_id},
        )
    return dict(row)


def get_source_file(engine: Engine, case_id: str, source_file_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = get_source_file_conn(conn, source_file_id)
    if row["case_id"] != case_id:
        raise MizarError(
            ErrorCode.FILE_NOT_FOUND,
            "Source file not found.",
            details={"source_file_id": source_file_id},
        )
    return row


def list_source_files(engine: Engine, case_id: str) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        require_case(conn, case_id)
        rows = conn.execute(
            select(source_files)
            .where(source_files.c.case_id == case_id)
            .order_by(source_files.c.sequence)
        ).mappings()
        return [dict(r) for r in rows]


def update_source_file(conn: Connection, source_file_id: str, **values: Any) -> None:
    conn.execute(
        update(source_files).where(source_files.c.source_file_id == source_file_id).values(**values)
    )


def queue_verification(engine: Engine, case_id: str) -> str:
    with engine.begin() as conn:
        require_case(conn, case_id)
        return queue.enqueue(conn, VERIFY_JOB, {"case_id": case_id}, case_id)


def verify_case_files(
    engine: Engine,
    store: EvidenceStore,
    case_id: str,
    on_progress: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    """Re-hash every blob of the case and record the result per source file."""
    with engine.connect() as conn:
        rows = conn.execute(
            select(source_files.c.source_file_id, source_files.c.blob_sha256)
            .where(source_files.c.case_id == case_id)
            .order_by(source_files.c.sequence)
        ).all()
    counts = {status.value: 0 for status in VerifyStatus}
    failures: list[dict[str, Any]] = []
    results: dict[str, VerifyStatus] = {}
    for index, (source_file_id, sha256) in enumerate(rows):
        if on_progress is not None:
            on_progress(index / max(len(rows), 1), f"Verifying file {index + 1} of {len(rows)}")
        # Several source files may share one blob; hash it once.
        if sha256 not in results:
            results[sha256] = store.verify(sha256).status
        status = results[sha256]
        counts[status.value] += 1
        if status is not VerifyStatus.VERIFIED:
            failures.append({"source_file_id": source_file_id, "status": status.value})
        with engine.begin() as conn:
            update_source_file(
                conn, source_file_id, integrity_status=status.value, last_verified_at=utc_now()
            )
    return {"files_checked": len(rows), "counts": counts, "failures": failures}
