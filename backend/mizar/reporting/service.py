"""Export requests, the render job, and finished export files (DESIGN.md §13).

A file is written as exports/<case_id>/.<export_id>.partial and renamed into place
only when complete, so exports/ never holds a partial report (§14.1).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, delete, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import new_export_id
from mizar.core.timeutil import utc_now
from mizar.db.tables import analysis_runs, cases, exports, jobs
from mizar.evidence.store import CHUNK_BYTES
from mizar.jobs import queue
from mizar.jobs.worker import JobCancelled, JobContext, WorkerStopping
from mizar.reporting.data import begin_snapshot, load_report_data, normalize_options
from mizar.reporting.pdf import render_pdf
from mizar.reporting.structured import write_csv_bundle, write_json_bundle

log = logging.getLogger(__name__)

EXPORT_JOB = "render_export"
_FINISHED_RUN = ("succeeded", "succeeded_with_errors")
_OPEN = ("queued", "running")


def _not_found(export_id: str) -> MizarError:
    return MizarError(
        ErrorCode.EXPORT_NOT_FOUND, "Export not found.", details={"export_id": export_id}
    )


def case_dir(exports_dir: Path, case_id: str) -> Path:
    return exports_dir / case_id


def _partial_path(exports_dir: Path, row: dict[str, Any]) -> Path:
    return case_dir(exports_dir, row["case_id"]) / f".{row['export_id']}.partial"


def start_export(
    engine: Engine, run_id: str, export_format: str, options: dict[str, Any]
) -> dict[str, Any]:
    if export_format == "pdf" and options.get("all_events"):
        raise MizarError(
            ErrorCode.VALIDATION_ERROR,
            "All events can only be exported as JSON or CSV; the PDF lists finding evidence.",
        )
    export_id = new_export_id()
    with engine.begin() as conn:
        run = conn.execute(
            select(analysis_runs.c.case_id, analysis_runs.c.status).where(
                analysis_runs.c.run_id == run_id
            )
        ).first()
        if run is None:
            raise MizarError(
                ErrorCode.RUN_NOT_FOUND, "Analysis run not found.", details={"run_id": run_id}
            )
        if run.status not in _FINISHED_RUN:
            raise MizarError(
                ErrorCode.RUN_NOT_FINISHED,
                "Only a finished analysis run can be exported.",
                details={"run_status": run.status},
            )
        analyst = conn.execute(
            select(cases.c.analyst_name).where(cases.c.case_id == run.case_id)
        ).scalar_one()
        conn.execute(
            insert(exports).values(
                export_id=export_id,
                case_id=run.case_id,
                run_id=run_id,
                format=export_format,
                status="queued",
                options=normalize_options(options),
                requested_by=analyst,
                created_at=utc_now(),
            )
        )
        job_id = queue.enqueue(conn, EXPORT_JOB, {"export_id": export_id}, run.case_id)
        conn.execute(update(exports).where(exports.c.export_id == export_id).values(job_id=job_id))
    return {"export_id": export_id, "job_id": job_id}


def _reconcile(
    engine: Engine, exports_dir: Path, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """An export whose job ended without finishing it follows the job, like runs do."""
    open_rows = {r["job_id"]: r for r in rows if r["status"] in _OPEN and r["job_id"]}
    if not open_rows:
        return rows
    with engine.begin() as conn:
        ended = conn.execute(
            select(jobs.c.job_id, jobs.c.status, jobs.c.error_code, jobs.c.error_message).where(
                jobs.c.job_id.in_(list(open_rows)), jobs.c.status.in_(("cancelled", "failed"))
            )
        ).all()
        for job_id, job_status, code, message in ended:
            row = open_rows[job_id]
            values = {
                "status": job_status,
                "finished_at": row["finished_at"] or utc_now(),
                "error_code": row["error_code"] or code,
                "error_message": row["error_message"] or message,
            }
            conn.execute(
                update(exports).where(exports.c.export_id == row["export_id"]).values(**values)
            )
            row.update(values)
            _partial_path(exports_dir, row).unlink(missing_ok=True)
    return rows


def list_exports(engine: Engine, exports_dir: Path, run_id: str) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        found = conn.execute(
            select(analysis_runs.c.run_id).where(analysis_runs.c.run_id == run_id)
        ).first()
        if found is None:
            raise MizarError(
                ErrorCode.RUN_NOT_FOUND, "Analysis run not found.", details={"run_id": run_id}
            )
        rows = [
            dict(r)
            for r in conn.execute(
                select(exports)
                .where(exports.c.run_id == run_id)
                .order_by(exports.c.created_at.desc())
            ).mappings()
        ]
    return _reconcile(engine, exports_dir, rows)


def get_export(engine: Engine, exports_dir: Path, export_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = (
            conn.execute(select(exports).where(exports.c.export_id == export_id)).mappings().first()
        )
    if row is None:
        raise _not_found(export_id)
    return _reconcile(engine, exports_dir, [dict(row)])[0]


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:40].strip("-")
    return slug or "case"


def download(engine: Engine, exports_dir: Path, export_id: str) -> tuple[Path, str, str]:
    """(path, media type, download filename) of a finished export."""
    row = get_export(engine, exports_dir, export_id)
    if row["status"] != "succeeded":
        raise MizarError(
            ErrorCode.EXPORT_NOT_READY,
            "The export is not ready.",
            details={"status": row["status"]},
        )
    path = case_dir(exports_dir, row["case_id"]) / row["file_name"]
    if not path.is_file():
        raise MizarError(
            ErrorCode.EXPORT_NOT_FOUND,
            "The export file is missing from the exports directory.",
            details={"export_id": export_id},
        )
    with engine.connect() as conn:
        name = conn.execute(
            select(cases.c.name).where(cases.c.case_id == row["case_id"])
        ).scalar_one()
    suffix = Path(row["file_name"]).suffix
    stamp = row["created_at"].strftime("%Y%m%dT%H%M%SZ")
    return path, row["media_type"], f"{_slug(name)}_{row['format']}_{stamp}{suffix}"


def delete_export(engine: Engine, exports_dir: Path, export_id: str) -> dict[str, Any]:
    row = get_export(engine, exports_dir, export_id)
    if row["status"] in _OPEN:
        raise MizarError(
            ErrorCode.EXPORT_BUSY,
            "The export is still being produced. Cancel its job first.",
            details={"job_id": row["job_id"]},
        )
    if row["file_name"]:
        (case_dir(exports_dir, row["case_id"]) / row["file_name"]).unlink(missing_ok=True)
    with engine.begin() as conn:
        conn.execute(delete(exports).where(exports.c.export_id == export_id))
    return {"export_id": export_id, "deleted": True}


# The job ----------------------------------------------------------------------------

_MEDIA = {
    ("pdf", False): ("application/pdf", ".pdf"),
    ("json", False): ("application/json", ".json"),
    ("json", True): ("application/zip", ".zip"),
    ("csv", False): ("application/zip", ".zip"),
    ("csv", True): ("application/zip", ".zip"),
}


def _set(engine: Engine, export_id: str, **values: Any) -> None:
    with engine.begin() as conn:
        conn.execute(update(exports).where(exports.c.export_id == export_id).values(**values))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def render_export_job(ctx: JobContext) -> dict[str, Any]:
    export_id: str = ctx.payload["export_id"]
    engine = ctx.deps.engine
    exports_dir = ctx.deps.settings.exports_dir
    with engine.connect() as conn:
        found = (
            conn.execute(select(exports).where(exports.c.export_id == export_id)).mappings().first()
        )
    if found is None:
        raise _not_found(export_id)
    row = dict(found)
    target_dir = case_dir(exports_dir, row["case_id"])
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    partial = _partial_path(exports_dir, row)
    partial.unlink(missing_ok=True)  # left by a crashed attempt
    _set(engine, export_id, status="running", error_code=None, error_message=None)
    try:
        result = _render(ctx, row, partial)
    except WorkerStopping:
        partial.unlink(missing_ok=True)
        _set(engine, export_id, status="queued")
        raise
    except JobCancelled:
        partial.unlink(missing_ok=True)
        _set(engine, export_id, status="cancelled", finished_at=utc_now())
        raise
    except MizarError as exc:
        partial.unlink(missing_ok=True)
        _set(
            engine,
            export_id,
            status="failed",
            finished_at=utc_now(),
            error_code=exc.code.value,
            error_message=exc.message,
        )
        raise
    except Exception as exc:
        partial.unlink(missing_ok=True)
        log.exception("export %s failed", export_id, extra={"case_id": row["case_id"]})
        message = f"The report could not be rendered ({type(exc).__name__})."
        _set(
            engine,
            export_id,
            status="failed",
            finished_at=utc_now(),
            error_code=ErrorCode.REPORT_RENDER_FAILED.value,
            error_message=message,
        )
        raise MizarError(ErrorCode.REPORT_RENDER_FAILED, message) from exc
    return result


def _render(ctx: JobContext, row: dict[str, Any], partial: Path) -> dict[str, Any]:
    engine = ctx.deps.engine
    export_id = row["export_id"]
    fmt = row["format"]
    options = row["options"]
    media_type, suffix = _MEDIA[(fmt, bool(options.get("all_events")))]

    def progress(message: str) -> None:
        ctx.progress(0.5, message)

    ctx.progress(0.05, "Reading findings and evidence")
    with engine.connect() as conn:
        begin_snapshot(conn)
        data = load_report_data(conn, row["run_id"], options, utc_now())
        ctx.check_cancelled()
        ctx.progress(0.3, "Writing the report")
        if fmt == "pdf":
            counts = render_pdf(partial, data, ctx.check_cancelled)
        elif fmt == "json":
            counts = write_json_bundle(partial, conn, ctx.deps.store, data, export_id, progress)
        else:
            counts = write_csv_bundle(partial, conn, data, export_id, progress)
    ctx.check_cancelled()

    with partial.open("rb") as fh:
        os.fsync(fh.fileno())
    os.chmod(partial, 0o400)
    file_name = f"{export_id}{suffix}"
    sha256 = _file_sha256(partial)
    size_bytes = partial.stat().st_size
    os.replace(partial, partial.with_name(file_name))
    summary = {
        **counts,
        "generated_at": data.generated_at.isoformat(),
        "findings_excluded": data.excluded,
    }
    _set(
        engine,
        export_id,
        status="succeeded",
        finished_at=utc_now(),
        file_name=file_name,
        media_type=media_type,
        size_bytes=size_bytes,
        sha256=sha256,
        summary=summary,
    )
    return {"export_id": export_id, "sha256": sha256, "size_bytes": size_bytes}
