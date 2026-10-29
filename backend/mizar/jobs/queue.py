"""Persistent job queue in the `jobs` table (DESIGN.md D8).

The API process enqueues; one worker process claims jobs one at a time with
an atomic UPDATE ... RETURNING, so a job can never run twice concurrently.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import Connection, Engine, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import new_job_id
from mizar.core.timeutil import utc_now
from mizar.db.tables import jobs

MAX_ATTEMPTS = 3


def enqueue(conn: Connection, job_type: str, payload: dict[str, Any], case_id: str | None) -> str:
    """Add a job inside the caller's transaction, so it commits with related rows."""
    job_id = new_job_id()
    conn.execute(
        insert(jobs).values(
            job_id=job_id,
            case_id=case_id,
            job_type=job_type,
            status="queued",
            progress=0.0,
            payload=payload,
            attempts=0,
            cancel_requested=False,
            created_at=utc_now(),
        )
    )
    return job_id


def claim_next(engine: Engine) -> dict[str, Any] | None:
    now = utc_now()
    next_job = (
        select(jobs.c.job_id)
        .where(jobs.c.status == "queued")
        .order_by(jobs.c.created_at, jobs.c.job_id)
        .limit(1)
        .scalar_subquery()
    )
    statement = (
        update(jobs)
        .where(jobs.c.job_id == next_job, jobs.c.status == "queued")
        .values(
            status="running",
            started_at=now,
            heartbeat_at=now,
            attempts=jobs.c.attempts + 1,
        )
        .returning(*jobs.c)
    )
    with engine.begin() as conn:
        row = conn.execute(statement).mappings().first()
    return dict(row) if row else None


def heartbeat(engine: Engine, job_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(jobs)
            .where(jobs.c.job_id == job_id, jobs.c.status == "running")
            .values(heartbeat_at=utc_now())
        )


def set_progress(engine: Engine, job_id: str, progress: float, message: str | None) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(jobs)
            .where(jobs.c.job_id == job_id)
            .values(progress=min(max(progress, 0.0), 1.0), progress_message=message)
        )


def is_cancel_requested(engine: Engine, job_id: str) -> bool:
    with engine.connect() as conn:
        return bool(
            conn.execute(select(jobs.c.cancel_requested).where(jobs.c.job_id == job_id)).scalar()
        )


def _finish(engine: Engine, job_id: str, **values: Any) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(jobs)
            .where(jobs.c.job_id == job_id, jobs.c.status == "running")
            .values(finished_at=utc_now(), **values)
        )


def mark_succeeded(engine: Engine, job_id: str, result: dict[str, Any]) -> None:
    _finish(engine, job_id, status="succeeded", progress=1.0, result=result)


def mark_failed(engine: Engine, job_id: str, code: ErrorCode, message: str) -> None:
    _finish(engine, job_id, status="failed", error_code=code.value, error_message=message)


def mark_cancelled(engine: Engine, job_id: str) -> None:
    _finish(
        engine,
        job_id,
        status="cancelled",
        error_code=ErrorCode.JOB_CANCELLED.value,
        error_message="Cancelled by the analyst.",
    )


def requeue(engine: Engine, job_id: str) -> None:
    """Return a running job to the queue (worker shutting down mid-job)."""
    with engine.begin() as conn:
        conn.execute(
            update(jobs)
            .where(jobs.c.job_id == job_id, jobs.c.status == "running")
            .values(status="queued", started_at=None, heartbeat_at=None)
        )


def request_cancel(engine: Engine, job_id: str) -> dict[str, Any]:
    with engine.begin() as conn:
        job = conn.execute(select(jobs).where(jobs.c.job_id == job_id)).mappings().first()
        if job is None:
            raise MizarError(ErrorCode.JOB_NOT_FOUND, "Job not found.", details={"job_id": job_id})
        if job["status"] == "queued":
            conn.execute(
                update(jobs)
                .where(jobs.c.job_id == job_id)
                .values(
                    status="cancelled",
                    cancel_requested=True,
                    finished_at=utc_now(),
                    error_code=ErrorCode.JOB_CANCELLED.value,
                    error_message="Cancelled by the analyst before it started.",
                )
            )
        elif job["status"] == "running":
            conn.execute(update(jobs).where(jobs.c.job_id == job_id).values(cancel_requested=True))
        else:
            raise MizarError(
                ErrorCode.JOB_NOT_CANCELLABLE,
                f"The job has already finished ({job['status']}).",
                details={"job_id": job_id, "status": job["status"]},
            )
        updated = conn.execute(select(jobs).where(jobs.c.job_id == job_id)).mappings().one()
    return dict(updated)


def recover_stale(engine: Engine, stale_after: timedelta) -> tuple[int, int]:
    """Handle jobs left 'running' by a crashed worker.

    Jobs under MAX_ATTEMPTS are requeued (handlers are idempotent); the rest
    fail with JOB_CRASHED. Returns (requeued, failed).
    """
    cutoff = utc_now() - stale_after
    with engine.begin() as conn:
        stale = conn.execute(
            select(jobs.c.job_id, jobs.c.attempts, jobs.c.heartbeat_at).where(
                jobs.c.status == "running"
            )
        ).all()
        requeued = failed = 0
        for job_id, attempts, beat in stale:
            if beat is not None and beat > cutoff:
                continue
            if attempts < MAX_ATTEMPTS:
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id)
                    .values(status="queued", started_at=None, heartbeat_at=None)
                )
                requeued += 1
            else:
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id)
                    .values(
                        status="failed",
                        finished_at=utc_now(),
                        error_code=ErrorCode.JOB_CRASHED.value,
                        error_message=f"The worker stopped unexpectedly {attempts} times.",
                    )
                )
                failed += 1
    return requeued, failed


def get_job(engine: Engine, job_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = conn.execute(select(jobs).where(jobs.c.job_id == job_id)).mappings().first()
    if row is None:
        raise MizarError(ErrorCode.JOB_NOT_FOUND, "Job not found.", details={"job_id": job_id})
    return dict(row)


def list_case_jobs(engine: Engine, case_id: str) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(jobs).where(jobs.c.case_id == case_id).order_by(jobs.c.created_at.desc())
        ).mappings()
        return [dict(r) for r in rows]
