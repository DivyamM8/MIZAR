"""Registers every job handler with the worker. Import once at worker start."""

from __future__ import annotations

from typing import Any

from mizar.evidence import service as evidence
from mizar.ingest.service import ingest_file_job
from mizar.jobs.worker import JobContext, register

register(evidence.INGEST_JOB)(ingest_file_job)


@register(evidence.VERIFY_JOB)
def verify_evidence_job(ctx: JobContext) -> dict[str, Any]:
    return evidence.verify_case_files(
        ctx.deps.engine, ctx.deps.store, ctx.payload["case_id"], on_progress=ctx.progress
    )
