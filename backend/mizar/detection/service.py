"""Run and finding queries, and analyst updates to findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, func, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.timeutil import utc_now
from mizar.db.tables import analysis_runs, cases, events, finding_events, findings, jobs
from mizar.detection.rules import CONFIDENCES, EVIDENCE_STRENGTHS, SEVERITIES
from mizar.evidence.service import require_case

FINDING_EVIDENCE_PAGE = 200
_SUMMARY_COLUMNS = [
    c
    for c in findings.columns
    if c.name not in ("observed_evidence", "alternative_explanations", "verification_steps")
]


def priority_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    """DESIGN.md §11.2: severity, then confidence, then evidence strength, then time."""
    first = finding["first_observed_utc"]
    return (
        -SEVERITIES.index(finding["severity"]),
        -CONFIDENCES.index(finding["confidence"]),
        EVIDENCE_STRENGTHS.index(finding["evidence_strength"]),
        first is None,
        first.isoformat() if first else "",
        finding["finding_id"],
    )


def _reconcile(engine: Engine, runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A run whose job ended without running it (e.g. cancelled while queued) follows the job."""
    open_runs = {
        r["job_id"]: r for r in runs if r["status"] in ("queued", "running") and r["job_id"]
    }
    if not open_runs:
        return runs
    with engine.begin() as conn:
        ended = conn.execute(
            select(jobs.c.job_id, jobs.c.status, jobs.c.error_code, jobs.c.error_message).where(
                jobs.c.job_id.in_(list(open_runs)), jobs.c.status.in_(("cancelled", "failed"))
            )
        ).all()
        for job_id, job_status, code, message in ended:
            run = open_runs[job_id]
            values = {
                "status": job_status,
                "finished_at": run["finished_at"] or utc_now(),
                "error_code": run["error_code"] or code,
                "error_message": run["error_message"] or message,
            }
            conn.execute(
                update(analysis_runs)
                .where(analysis_runs.c.run_id == run["run_id"])
                .values(**values)
            )
            run.update(values)
    return runs


def list_runs(engine: Engine, case_id: str) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        require_case(conn, case_id)
        rows = conn.execute(
            select(analysis_runs)
            .where(analysis_runs.c.case_id == case_id)
            .order_by(analysis_runs.c.created_at.desc())
        ).mappings()
        runs = [dict(r) for r in rows]
    return _reconcile(engine, runs)


def get_run(engine: Engine, run_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = (
            conn.execute(select(analysis_runs).where(analysis_runs.c.run_id == run_id))
            .mappings()
            .first()
        )
    if row is None:
        raise MizarError(
            ErrorCode.RUN_NOT_FOUND, "Analysis run not found.", details={"run_id": run_id}
        )
    return _reconcile(engine, [dict(row)])[0]


def list_findings(
    engine: Engine,
    run_id: str,
    *,
    severity: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
) -> list[dict[str, Any]]:
    get_run(engine, run_id)
    query = select(*_SUMMARY_COLUMNS).where(findings.c.run_id == run_id)
    if severity:
        query = query.where(findings.c.severity == severity)
    if status:
        query = query.where(findings.c.status == status)
    if rule_id:
        query = query.where(findings.c.rule_id == rule_id)
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(query).mappings()]
    return sorted(rows, key=priority_key)


def get_finding(engine: Engine, finding_id_value: str, offset: int = 0) -> dict[str, Any]:
    with engine.connect() as conn:
        row = (
            conn.execute(select(findings).where(findings.c.finding_id == finding_id_value))
            .mappings()
            .first()
        )
        if row is None:
            raise MizarError(
                ErrorCode.FINDING_NOT_FOUND,
                "Finding not found.",
                details={"finding_id": finding_id_value},
            )
        linked = conn.execute(
            select(func.count()).where(finding_events.c.finding_id == finding_id_value)
        ).scalar_one()
        page = conn.execute(
            select(
                finding_events.c.event_id,
                finding_events.c.role,
                events.c.timestamp_utc,
                events.c.timestamp_original,
                events.c.timezone_assumption,
                events.c.source_file_id,
                events.c.hostname,
                events.c.username,
                events.c.source_ip,
                events.c.destination_ip,
                events.c.destination_port,
                events.c.event_type,
                events.c.event_outcome,
                events.c.event_code,
                events.c.message,
            )
            .select_from(finding_events)
            .outerjoin(events, events.c.event_id == finding_events.c.event_id)
            .where(finding_events.c.finding_id == finding_id_value)
            .order_by(finding_events.c.position)
            .limit(FINDING_EVIDENCE_PAGE)
            .offset(max(offset, 0))
        ).mappings()
        evidence = [
            {
                **dict(r),
                "present": r["timestamp_original"] is not None or r["event_type"] is not None,
            }
            for r in page
        ]
    result = dict(row)
    result["evidence_events"] = evidence
    result["evidence_total"] = linked
    result["evidence_offset"] = offset
    return result


def update_finding(
    engine: Engine, finding_id_value: str, changes: dict[str, Any]
) -> dict[str, Any]:
    with engine.begin() as conn:
        row = conn.execute(
            select(findings.c.case_id).where(findings.c.finding_id == finding_id_value)
        ).first()
        if row is None:
            raise MizarError(
                ErrorCode.FINDING_NOT_FOUND,
                "Finding not found.",
                details={"finding_id": finding_id_value},
            )
        analyst = conn.execute(
            select(cases.c.analyst_name).where(cases.c.case_id == row.case_id)
        ).scalar_one()
        if changes:
            conn.execute(
                update(findings)
                .where(findings.c.finding_id == finding_id_value)
                .values(
                    **changes, updated_by=analyst, updated_at=utc_now(), status_carried_from=None
                )
            )
    return get_finding(engine, finding_id_value)
