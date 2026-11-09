"""Analysis runs: reproducible executions of the rule set over a case (DESIGN.md §12)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, delete, func, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import finding_id, new_run_id
from mizar.core.timeutil import utc_now
from mizar.db.tables import (
    analysis_runs,
    events,
    finding_events,
    findings,
    jobs,
    parse_results,
    source_files,
)
from mizar.detection.engine import EVIDENCE_CAP, Candidate, Detector, build_finding
from mizar.detection.rules import CONFIDENCES, SEVERITIES, Rule, load_rules
from mizar.evidence.service import require_case, verify_case_files
from mizar.ingest.formats import GENERIC_FORMATS
from mizar.jobs import queue
from mizar.jobs.worker import JobCancelled, JobContext, WorkerStopping
from mizar.versions import EVENT_SCHEMA_VERSION, MIZAR_VERSION, RULE_FORMAT_VERSION

log = logging.getLogger(__name__)

ANALYSIS_JOB = "analysis_run"
# A rule matching more often than this is noise no analyst can review; the rest are counted
# and the run says which parameters to adjust (DESIGN.md D49).
MAX_FINDINGS_PER_RULE = 1000
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_INPUT_JOB_TYPES = ("ingest_file", "parse_file")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def effective_params(overrides: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rules = {rule.id: rule for rule in load_rules()}
    unknown = set(overrides) - set(rules)
    if unknown:
        raise MizarError(
            ErrorCode.RULE_PARAM_INVALID,
            f"Unknown rule(s) {sorted(unknown)}.",
            details={"rules": sorted(unknown)},
        )
    return {
        rule_id: rule.effective_params(overrides.get(rule_id, {}))
        for rule_id, rule in rules.items()
    }


def start_run(engine: Engine, case_id: str, overrides: dict[str, dict[str, Any]]) -> dict[str, Any]:
    effective_params(overrides)  # validate before queueing
    run_id = new_run_id()
    with engine.begin() as conn:
        case = require_case(conn, case_id)
        files = conn.execute(
            select(func.count()).where(source_files.c.case_id == case_id)
        ).scalar_one()
        if not files:
            raise MizarError(
                ErrorCode.RUN_INPUTS_NOT_READY, "The case has no evidence files to analyze."
            )
        pending = conn.execute(
            select(func.count()).where(
                jobs.c.case_id == case_id,
                jobs.c.job_type.in_(_INPUT_JOB_TYPES),
                jobs.c.status.in_(("queued", "running")),
            )
        ).scalar_one()
        if pending:
            raise MizarError(
                ErrorCode.RUN_INPUTS_NOT_READY,
                "Evidence is still being ingested or parsed; start the analysis when it finishes.",
                details={"pending_jobs": pending},
            )
        conn.execute(
            insert(analysis_runs).values(
                run_id=run_id,
                case_id=case_id,
                status="queued",
                triggered_by=case["analyst_name"],
                created_at=utc_now(),
                overrides=overrides,
            )
        )
        job_id = queue.enqueue(conn, ANALYSIS_JOB, {"run_id": run_id}, case_id)
        conn.execute(
            update(analysis_runs).where(analysis_runs.c.run_id == run_id).values(job_id=job_id)
        )
    return {"run_id": run_id, "job_id": job_id}


def _set_run(engine: Engine, run_id: str, **values: Any) -> None:
    with engine.begin() as conn:
        conn.execute(update(analysis_runs).where(analysis_runs.c.run_id == run_id).values(**values))


def analysis_run_job(ctx: JobContext) -> dict[str, Any]:
    run_id: str = ctx.payload["run_id"]
    engine = ctx.deps.engine
    with engine.connect() as conn:
        run = (
            conn.execute(select(analysis_runs).where(analysis_runs.c.run_id == run_id))
            .mappings()
            .first()
        )
    if run is None:
        raise MizarError(
            ErrorCode.RUN_NOT_FOUND, "Analysis run not found.", details={"run_id": run_id}
        )
    _set_run(
        engine, run_id, status="running", started_at=utc_now(), error_code=None, error_message=None
    )
    try:
        return _execute(ctx, dict(run))
    except WorkerStopping:
        _set_run(engine, run_id, status="queued", started_at=None)
        raise
    except JobCancelled:
        _set_run(engine, run_id, status="cancelled", finished_at=utc_now())
        raise
    except MizarError as exc:
        _set_run(
            engine,
            run_id,
            status="failed",
            finished_at=utc_now(),
            error_code=exc.code.value,
            error_message=exc.message,
            results={"error_details": exc.details},
        )
        raise
    except Exception:
        _set_run(
            engine,
            run_id,
            status="failed",
            finished_at=utc_now(),
            error_code=ErrorCode.INTERNAL_ERROR.value,
            error_message=(
                f"The analysis stopped unexpectedly. See the application log for job {ctx.job_id}."
            ),
        )
        raise


def _inputs(engine: Engine, case_id: str) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(
                source_files.c.source_file_id,
                source_files.c.blob_sha256,
                source_files.c.original_filename,
                source_files.c.archive_member_path,
                source_files.c.parent_file_id,
                source_files.c.status,
                source_files.c.container_type,
                source_files.c.detected_format,
                source_files.c.format_override,
                source_files.c.integrity_status,
                source_files.c.last_verified_at,
                parse_results.c.parse_result_id,
                parse_results.c.parser_name,
                parse_results.c.parser_version,
                parse_results.c.status.label("parse_status"),
                parse_results.c.records_total,
                parse_results.c.records_partial,
                parse_results.c.records_unparsed,
                parse_results.c.timezone_hint,
                parse_results.c.year_hint,
                parse_results.c.file_problems,
            )
            .select_from(source_files)
            .outerjoin(
                parse_results,
                (parse_results.c.source_file_id == source_files.c.source_file_id)
                & parse_results.c.is_current.is_(True),
            )
            .where(source_files.c.case_id == case_id)
            .order_by(source_files.c.sequence)
        ).mappings()
        return [
            {
                "source_file_id": r["source_file_id"],
                "sha256": r["blob_sha256"],
                "filename": r["archive_member_path"] or r["original_filename"],
                "parent_file_id": r["parent_file_id"],
                "status": r["status"],
                "container_type": r["container_type"],
                "format": r["format_override"] or r["detected_format"],
                "integrity_status": r["integrity_status"],
                "verified_at": r["last_verified_at"].isoformat() if r["last_verified_at"] else None,
                "parse_result_id": r["parse_result_id"],
                "parser_name": r["parser_name"],
                "parser_version": r["parser_version"],
                "parse_status": r["parse_status"],
                "records_total": r["records_total"],
                "records_partial": r["records_partial"],
                "records_unparsed": r["records_unparsed"],
                "timezone_hint": r["timezone_hint"],
                "year_hint": r["year_hint"],
                "file_problems": (r["file_problems"] or {}).get("counts", {}),
            }
            for r in rows
        ]


def _coverage_gaps(
    inputs: list[dict[str, Any]], engine: Engine, case_id: str
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for item in inputs:
        reason = None
        if item["status"] == "unsupported":
            reason = "Kept as evidence but not analyzed (unsupported content or archive limit)."
        elif item["status"] == "failed":
            reason = "Ingestion failed; the file was not analyzed."
        elif item["container_type"] is None and item["parse_status"] == "failed":
            reason = "Parsing stopped early; only records before the failure were analyzed."
        elif item["format"] in GENERIC_FORMATS:
            reason = "No specific parser; only generic fields were extracted."
        elif item["file_problems"]:
            reason = "Parts of the file could not be read: " + ", ".join(
                f"{code} x{count}" for code, count in sorted(item["file_problems"].items())
            )
        elif item["records_unparsed"]:
            reason = f"{item['records_unparsed']} record(s) could not be parsed."
        if reason:
            gaps.append(
                {
                    "source_file_id": item["source_file_id"],
                    "filename": item["filename"],
                    "reason": reason,
                }
            )
    with engine.connect() as conn:
        unplaced = conn.execute(
            select(func.count()).where(
                events.c.case_id == case_id, events.c.timestamp_utc.is_(None)
            )
        ).scalar_one()
    if unplaced:
        gaps.append(
            {
                "source_file_id": None,
                "filename": None,
                "reason": f"{unplaced} event(s) have no reliable UTC time and are excluded from "
                "time-window rules (supply timezone/year hints and re-parse to include them).",
            }
        )
    return gaps


def _execute(ctx: JobContext, run: dict[str, Any]) -> dict[str, Any]:
    deps = ctx.deps
    engine = deps.engine
    run_id = run["run_id"]
    case_id = run["case_id"]
    started = time.monotonic()

    # 1. Evidence must still match its hashes (DESIGN.md §6.2).
    verification = verify_case_files(
        engine, deps.store, case_id, on_progress=lambda f, m: ctx.progress(f * 0.3, m)
    )
    if verification["failures"]:
        raise MizarError(
            ErrorCode.EVIDENCE_INTEGRITY_MISMATCH,
            "Evidence no longer matches its recorded hashes; the analysis was not run.",
            details={"failures": verification["failures"]},
        )

    # 2. Manifest: everything that determines the result.
    rules = load_rules()
    rule_by_id = {rule.id: rule for rule in rules}
    params = effective_params(run["overrides"])
    inputs = _inputs(engine, case_id)
    config = {
        "count_duplicates_once": True,
        "evidence_cap_per_finding": EVIDENCE_CAP,
        "max_findings_per_rule": MAX_FINDINGS_PER_RULE,
    }
    versions = {
        "mizar_version": MIZAR_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "rule_format_version": RULE_FORMAT_VERSION,
    }
    rule_list = [
        {"rule_id": r.id, "rule_version": r.version, "rule_file_sha256": r.file_sha256}
        for r in rules
    ]
    determinants = {
        "inputs": [{k: v for k, v in i.items() if k != "verified_at"} for i in inputs],
        "rules": rule_list,
        "params": params,
        "config": config,
        "versions": versions,
    }
    inputs_fingerprint = _sha256(determinants)

    # 3. Rules. One failing rule is recorded and does not stop the others.
    candidates: dict[str, list[Candidate]] = {}
    rule_errors: list[dict[str, Any]] = []
    with engine.connect() as conn:
        detector = Detector(conn, case_id, params)
        ordered = [r for r in rules if r.type != "correlation"] + [
            r for r in rules if r.type == "correlation"
        ]
        for index, rule in enumerate(ordered):
            ctx.progress(0.3 + 0.6 * index / len(ordered), f"Rule {rule.id}")
            try:
                candidates[rule.id] = detector.run(rule, candidates)
            except (JobCancelled, WorkerStopping):
                raise
            except Exception as exc:
                log.exception(
                    "rule %s failed", rule.id, extra={"run_id": run_id, "case_id": case_id}
                )
                rule_errors.append(
                    {"rule_id": rule.id, "error": type(exc).__name__, "message": str(exc)[:300]}
                )
                candidates[rule.id] = []
        events_evaluated = conn.execute(
            select(func.count()).where(events.c.case_id == case_id)
        ).scalar_one()

        # 4. Findings, in a deterministic order (§12.2). Each fetches its evidence events.
        built = [
            build_finding(candidate, params[candidate.rule.id], detector.fetch)
            for rule in rules
            for candidate in candidates.get(rule.id, [])
        ]
    built, capped = _cap_per_rule(built, rules)
    for rule_id, counts in capped.items():
        names = ", ".join(sorted(rule_by_id[rule_id].params)) or "its filter"
        detector.notes[rule_id]["findings_capped"] = (
            f"Matched {counts['matched']} times; the {counts['kept']} with the highest severity "
            f"and confidence, then the earliest, were kept. Adjust {names} to narrow it."
        )
    built.sort(
        key=lambda f: (
            f["rule_id"],
            f["first_observed_utc"] is None,
            f["first_observed_utc"] or _EPOCH,
            f["fingerprint"],
        )
    )
    _persist(engine, run_id, case_id, built, inputs)

    by_severity = Counter(f["severity"] for f in built)
    results = {
        "findings_total": len(built),
        "findings_by_severity": {
            level: by_severity.get(level, 0) for level in reversed(SEVERITIES)
        },
        "findings_by_rule": dict(sorted(Counter(f["rule_id"] for f in built).items())),
        "events_evaluated": events_evaluated,
        "rule_errors": rule_errors,
        "findings_capped": capped,
        "rule_notes": dict(sorted(detector.notes.items())),
        "coverage_gaps": _coverage_gaps(inputs, engine, case_id),
        "evidence_verification": verification["counts"],
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    finished = utc_now()
    manifest = {
        "run_id": run_id,
        "case_id": case_id,
        "triggered_by": run["triggered_by"],
        "started_at": run["created_at"].isoformat(),
        **versions,
        "inputs": inputs,
        "rules": rule_list,
        "params": params,
        "overrides": run["overrides"],
        "config": config,
        "inputs_fingerprint": inputs_fingerprint,
    }
    status = "succeeded_with_errors" if rule_errors else "succeeded"
    _set_run(
        engine,
        run_id,
        status=status,
        finished_at=finished,
        manifest=manifest,
        manifest_sha256=_sha256(manifest),
        inputs_fingerprint=inputs_fingerprint,
        results=results,
    )
    return {"run_id": run_id, "status": status, "findings_total": len(built)}


def _cap_per_rule(
    built: list[dict[str, Any]], rules: tuple[Rule, ...]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    """At most MAX_FINDINGS_PER_RULE findings per rule: the highest severity and confidence,
    then the earliest. Findings that a kept correlation finding chains are always kept."""
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in built:
        by_rule[finding["rule_id"]].append(finding)

    def rank(finding: dict[str, Any]) -> tuple[Any, ...]:
        first = finding["first_observed_utc"]
        return (
            -SEVERITIES.index(finding["severity"]),
            -CONFIDENCES.index(finding["confidence"]),
            first is None,
            first or _EPOCH,
            finding["fingerprint"],
        )

    kept: dict[str, list[dict[str, Any]]] = {}
    capped: dict[str, dict[str, int]] = {}
    correlation = [r.id for r in rules if r.type == "correlation"]
    others = [r.id for r in rules if r.type != "correlation"]
    chained: set[str] = set()
    for rule_id in correlation + others:  # correlation first: they decide what is chained
        found = sorted(by_rule.get(rule_id, []), key=rank)
        if len(found) > MAX_FINDINGS_PER_RULE:
            keep = found[:MAX_FINDINGS_PER_RULE] + [
                f for f in found[MAX_FINDINGS_PER_RULE:] if f["fingerprint"] in chained
            ]
            capped[rule_id] = {"matched": len(found), "kept": len(keep)}
            found = keep
        kept[rule_id] = found
        if rule_id in correlation:
            for finding in found:
                chained.update(finding["related_fingerprints"])
    return [f for rule_id in kept for f in kept[rule_id]], capped


def _persist(
    engine: Engine,
    run_id: str,
    case_id: str,
    built: list[dict[str, Any]],
    inputs: list[dict[str, Any]],
) -> None:
    files = {i["source_file_id"]: i for i in inputs}
    ids = {f["fingerprint"]: finding_id(run_id, n) for n, f in enumerate(built, start=1)}
    with engine.begin() as conn:
        # Retry safety: a re-executed run replaces its own findings.
        conn.execute(delete(findings).where(findings.c.run_id == run_id))
        carried = _previous_status(conn, case_id, run_id, list(ids))
        rows: list[dict[str, Any]] = []
        links: list[dict[str, Any]] = []
        for item in built:
            fid = ids[item["fingerprint"]]
            previous = carried.get(item["fingerprint"])
            rows.append(
                {
                    "finding_id": fid,
                    "run_id": run_id,
                    "case_id": case_id,
                    **{
                        k: item[k]
                        for k in (
                            "fingerprint",
                            "rule_id",
                            "rule_version",
                            "title",
                            "description",
                            "severity",
                            "severity_rationale",
                            "confidence",
                            "confidence_rationale",
                            "evidence_strength",
                            "attack_techniques",
                            "first_observed_utc",
                            "last_observed_utc",
                            "entities",
                            "observed_evidence",
                            "interpretation",
                            "alternative_explanations",
                            "verification_steps",
                            "event_count",
                        )
                    },
                    "source_files": [
                        {
                            "source_file_id": file_id,
                            "sha256": files[file_id]["sha256"] if file_id in files else None,
                            "filename": files[file_id]["filename"] if file_id in files else None,
                        }
                        for file_id in item["evidence_files"]
                    ],
                    "related_finding_ids": [
                        ids[fp] for fp in item["related_fingerprints"] if fp in ids
                    ],
                    "status": previous["status"] if previous else "open",
                    "analyst_notes": previous["analyst_notes"] if previous else None,
                    "status_carried_from": previous["finding_id"] if previous else None,
                    "updated_by": previous["updated_by"] if previous else None,
                    "updated_at": previous["updated_at"] if previous else None,
                }
            )
            links.extend(
                {"finding_id": fid, "event_id": event_id, "role": role, "position": position}
                for position, (event_id, role) in enumerate(item["evidence"])
            )
        if rows:
            conn.execute(insert(findings), rows)
        for start in range(0, len(links), 5000):
            conn.execute(insert(finding_events), links[start : start + 5000])


def _previous_status(
    conn: Any, case_id: str, run_id: str, fingerprints: list[str]
) -> dict[str, dict[str, Any]]:
    """Latest analyst-reviewed state per fingerprint from earlier runs (§11.5).

    Reviewed findings are few, so they are all read and matched here; a run can have
    more findings than SQLite allows variables in an IN (...) list.
    """
    if not fingerprints:
        return {}
    wanted = set(fingerprints)
    rows = conn.execute(
        select(
            findings.c.fingerprint,
            findings.c.finding_id,
            findings.c.status,
            findings.c.analyst_notes,
            findings.c.updated_by,
            findings.c.updated_at,
        )
        .join(analysis_runs, analysis_runs.c.run_id == findings.c.run_id)
        .where(
            findings.c.case_id == case_id,
            findings.c.run_id != run_id,
            findings.c.updated_at.is_not(None),
        )
        .order_by(findings.c.updated_at.desc())
    ).mappings()
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["fingerprint"] in wanted:
            latest.setdefault(row["fingerprint"], dict(row))
    return latest
