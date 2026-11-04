"""Registers every job handler with the worker. Import once at worker start."""

from __future__ import annotations

from typing import Any

from mizar.correlation.index import INDEX_JOB, rebuild_case_index
from mizar.detection.runs import ANALYSIS_JOB, analysis_run_job
from mizar.evidence import service as evidence
from mizar.ingest.parse import PARSE_JOB, abort_parse, parse_file_job
from mizar.ingest.service import abort_ingest, ingest_file_job
from mizar.jobs.worker import JobContext, register, register_abort
from mizar.reporting.service import EXPORT_JOB, render_export_job

register(evidence.INGEST_JOB)(ingest_file_job)
register(PARSE_JOB)(parse_file_job)
register(ANALYSIS_JOB)(analysis_run_job)
register(EXPORT_JOB)(render_export_job)
register_abort(PARSE_JOB)(abort_parse)
register_abort(evidence.INGEST_JOB)(abort_ingest)


@register(INDEX_JOB)
def index_case_job(ctx: JobContext) -> dict[str, Any]:
    return rebuild_case_index(ctx.deps.engine, ctx.payload["case_id"])


@register(evidence.VERIFY_JOB)
def verify_evidence_job(ctx: JobContext) -> dict[str, Any]:
    return evidence.verify_case_files(
        ctx.deps.engine, ctx.deps.store, ctx.payload["case_id"], on_progress=ctx.progress
    )
