"""Background job endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from mizar.api.deps import EngineDep
from mizar.api.schemas import JobOut
from mizar.evidence.service import require_case
from mizar.jobs import queue

router = APIRouter(tags=["jobs"])


def _out(row: dict[str, object]) -> JobOut:
    return JobOut.model_validate(
        {k: v for k, v in row.items() if k not in ("payload", "heartbeat_at")}
    )


@router.get("/api/jobs/{job_id}")
def get_job(job_id: str, engine: EngineDep) -> JobOut:
    return _out(queue.get_job(engine, job_id))


@router.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, engine: EngineDep) -> JobOut:
    return _out(queue.request_cancel(engine, job_id))


@router.get("/api/cases/{case_id}/jobs")
def list_case_jobs(case_id: str, engine: EngineDep) -> list[JobOut]:
    with engine.connect() as conn:
        require_case(conn, case_id)
    return [_out(row) for row in queue.list_case_jobs(engine, case_id)]
