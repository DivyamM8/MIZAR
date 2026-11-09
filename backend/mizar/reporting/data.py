"""The facts a report states, read once from one database snapshot (DESIGN.md §13).

The PDF, JSON and CSV writers all render the same ReportData, so the three
formats never disagree about what a run found or which findings were included.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from typing import Any

from sqlalchemy import Connection, func, select

from mizar.db.tables import (
    analysis_runs,
    cases,
    events,
    finding_events,
    findings,
    parse_results,
    source_files,
)
from mizar.detection.rules import SEVERITIES
from mizar.detection.service import priority_key

FINDING_STATUSES = ("open", "investigating", "confirmed", "false_positive", "resolved")
ENTITY_FIELDS = {
    "host": ("hostname",),
    "user": ("username",),
    "ip": ("source_ip", "destination_ip"),
}
_EVENT_ORDER = (events.c.timestamp_utc, events.c.source_file_id, events.c.record_index)


@dataclass
class ReportData:
    generated_at: datetime
    options: dict[str, Any]
    case: dict[str, Any]
    run: dict[str, Any]
    # Included findings in priority order, each with "evidence": [(event_id, role), ...].
    findings: list[dict[str, Any]]
    # Every finding of the run, before filters: {severity: {status: count}}.
    run_counts: dict[str, dict[str, int]]
    excluded: dict[str, int]
    # The events the PDF shows (the first evidence_limit of each finding), by ID.
    events: dict[str, dict[str, Any]]
    # Every event linked to an included finding that still exists, in timeline order;
    # JSON and CSV stream them with iter_linked_events().
    linked_ids: list[str]
    source_files: list[dict[str, Any]]
    events_total: int
    events_unplaced: int
    span: tuple[datetime | None, datetime | None]
    timezone_assumptions: dict[str, int]
    changed_since_run: list[str] = field(default_factory=list)

    @property
    def manifest(self) -> dict[str, Any]:
        return self.run.get("manifest") or {}

    @property
    def results(self) -> dict[str, Any]:
        return self.run.get("results") or {}

    def short_id(self, finding_id: str) -> str:
        """F0012 for RUN-...-F0012; reports name the run once."""
        return finding_id.rsplit("-", 1)[-1]

    @cached_property
    def present(self) -> frozenset[str]:
        return frozenset(self.linked_ids)

    def timeline(self) -> list[dict[str, Any]]:
        """The events the PDF shows, in stable time order, unplaced events last."""
        per_finding = self.options["evidence_limit"]
        linked: dict[str, list[str]] = defaultdict(list)
        for finding in self.findings:
            for event_id, _ in finding["evidence"][:per_finding]:
                if finding["finding_id"] not in linked[event_id]:
                    linked[event_id].append(finding["finding_id"])
        rows = [
            {**self.events[eid], "finding_ids": ids}
            for eid, ids in linked.items()
            if eid in self.events
        ]
        rows.sort(
            key=lambda e: (
                e["timestamp_utc"] is None,
                e["timestamp_utc"] or datetime.min,
                e["source_file_id"],
                e["record_index"],
            )
        )
        return rows

    def entities(self) -> dict[str, list[dict[str, Any]]]:
        """Hosts, users and IPs named by the included findings, most findings first."""
        result: dict[str, list[dict[str, Any]]] = {}
        for kind, names in ENTITY_FIELDS.items():
            seen: dict[str, dict[str, Any]] = {}
            for finding in self.findings:
                values: set[str] = set()
                for name in names:
                    value = finding["entities"].get(name)
                    if isinstance(value, list):
                        values.update(str(v) for v in value)
                    elif value is not None:
                        values.add(str(value))
                for value in values:
                    entry = seen.setdefault(
                        value, {"value": value, "finding_ids": [], "max_severity": "informational"}
                    )
                    entry["finding_ids"].append(finding["finding_id"])
                    if SEVERITIES.index(finding["severity"]) > SEVERITIES.index(
                        entry["max_severity"]
                    ):
                        entry["max_severity"] = finding["severity"]
            result[kind] = sorted(
                seen.values(),
                key=lambda e: (
                    -len(e["finding_ids"]),
                    -SEVERITIES.index(e["max_severity"]),
                    e["value"],
                ),
            )
        return result


def normalize_options(options: dict[str, Any]) -> dict[str, Any]:
    statuses = options.get("statuses")
    return {
        "statuses": sorted(statuses or FINDING_STATUSES, key=FINDING_STATUSES.index),
        "min_severity": options.get("min_severity") or "informational",
        "marking": options.get("marking") or "draft",
        "evidence_limit": options.get("evidence_limit") or 10,
        "all_events": bool(options.get("all_events")),
    }


def begin_snapshot(conn: Connection) -> None:
    """Start a read transaction so every query sees the same database state.

    The sqlite3 module only opens transactions before writes; in WAL mode an
    explicit BEGIN pins one snapshot until the connection is closed.
    """
    conn.exec_driver_sql("BEGIN")


def load_report_data(
    conn: Connection, run_id: str, options: dict[str, Any], generated_at: datetime
) -> ReportData:
    opts = normalize_options(options)
    run = dict(
        conn.execute(select(analysis_runs).where(analysis_runs.c.run_id == run_id)).mappings().one()
    )
    case = dict(
        conn.execute(select(cases).where(cases.c.case_id == run["case_id"])).mappings().one()
    )

    all_findings = [
        dict(r)
        for r in conn.execute(select(findings).where(findings.c.run_id == run_id)).mappings()
    ]
    run_counts = {level: dict.fromkeys(FINDING_STATUSES, 0) for level in reversed(SEVERITIES)}
    for finding in all_findings:
        run_counts[finding["severity"]][finding["status"]] += 1

    floor = SEVERITIES.index(opts["min_severity"])
    excluded = {"by_status": 0, "by_severity": 0}
    included = []
    for finding in all_findings:
        if SEVERITIES.index(finding["severity"]) < floor:
            excluded["by_severity"] += 1
        elif finding["status"] not in opts["statuses"]:
            excluded["by_status"] += 1
        else:
            included.append(finding)
    included.sort(key=priority_key)

    evidence: dict[str, list[tuple[str, str]]] = defaultdict(list)
    if included:
        rows = conn.execute(
            select(finding_events.c.finding_id, finding_events.c.event_id, finding_events.c.role)
            .join(findings, findings.c.finding_id == finding_events.c.finding_id)
            .where(findings.c.run_id == run_id)
            .order_by(finding_events.c.finding_id, finding_events.c.position)
        )
        wanted = {f["finding_id"] for f in included}
        for finding_id, event_id, role in rows:
            if finding_id in wanted:
                evidence[finding_id].append((event_id, role))
    for finding in included:
        finding["evidence"] = evidence.get(finding["finding_id"], [])

    linked_ids = _linked_ids(conn, run_id, opts)
    shown = sorted({eid for f in included for eid, _ in f["evidence"][: opts["evidence_limit"]]})
    event_rows: dict[str, dict[str, Any]] = {}
    for start in range(0, len(shown), 500):
        chunk = shown[start : start + 500]
        for row in conn.execute(select(events).where(events.c.event_id.in_(chunk))).mappings():
            event_rows[row["event_id"]] = dict(row)

    files = _source_files(conn, run)
    run_file_ids = [f["source_file_id"] for f in files]
    span = conn.execute(
        select(func.min(events.c.timestamp_utc), func.max(events.c.timestamp_utc)).where(
            events.c.case_id == case["case_id"], events.c.source_file_id.in_(run_file_ids)
        )
    ).one()
    total, unplaced = conn.execute(
        select(
            func.count(),
            func.count().filter(events.c.timestamp_utc.is_(None)),
        ).where(events.c.case_id == case["case_id"], events.c.source_file_id.in_(run_file_ids))
    ).one()
    zones: dict[Any, int] = dict(
        conn.execute(
            select(events.c.timezone_assumption, func.count())
            .where(events.c.case_id == case["case_id"], events.c.source_file_id.in_(run_file_ids))
            .group_by(events.c.timezone_assumption)
            .order_by(events.c.timezone_assumption)
        ).all()
    )
    return ReportData(
        generated_at=generated_at,
        options=opts,
        case=case,
        run=run,
        findings=included,
        run_counts=run_counts,
        excluded=excluded,
        events=event_rows,
        linked_ids=linked_ids,
        source_files=files,
        events_total=total,
        events_unplaced=unplaced,
        span=(span[0], span[1]),
        timezone_assumptions={str(k): v for k, v in zones.items()},
        changed_since_run=_changes_since_run(conn, run, files),
    )


def _source_files(conn: Connection, run: dict[str, Any]) -> list[dict[str, Any]]:
    """The run's inputs as recorded in its manifest, with the file details still on record."""
    inputs = (run.get("manifest") or {}).get("inputs", [])
    ids = [i["source_file_id"] for i in inputs]
    details = {
        r["source_file_id"]: dict(r)
        for r in conn.execute(
            select(
                source_files.c.source_file_id,
                source_files.c.sequence,
                source_files.c.original_filename,
                source_files.c.archive_member_path,
                source_files.c.size_bytes,
                source_files.c.ingestion_time,
                source_files.c.encoding,
                source_files.c.detection_confidence,
            ).where(source_files.c.source_file_id.in_(ids))
        ).mappings()
    }
    result = []
    for item in inputs:
        info = details.get(item["source_file_id"], {})
        result.append(
            {
                **item,
                "sequence": info.get("sequence"),
                "original_filename": info.get("original_filename"),
                "archive_member_path": info.get("archive_member_path"),
                "size_bytes": info.get("size_bytes"),
                "ingestion_time": info.get("ingestion_time"),
                "encoding": info.get("encoding"),
                "still_present": bool(info),
            }
        )
    return result


def _changes_since_run(
    conn: Connection, run: dict[str, Any], files: list[dict[str, Any]]
) -> list[str]:
    """Plain statements of how the case differs from what the run analyzed."""
    changes = []
    recorded = {f["source_file_id"]: f["parse_result_id"] for f in files}
    current = dict(
        conn.execute(
            select(source_files.c.source_file_id, parse_results.c.parse_result_id)
            .select_from(source_files)
            .outerjoin(
                parse_results,
                (parse_results.c.source_file_id == source_files.c.source_file_id)
                & parse_results.c.is_current.is_(True),
            )
            .where(source_files.c.case_id == run["case_id"])
        ).all()
    )
    added = sorted(set(current) - set(recorded))
    removed = sorted(set(recorded) - set(current))
    reparsed = sorted(k for k in set(recorded) & set(current) if recorded[k] != current[k])
    if added:
        changes.append(
            f"{len(added)} source file(s) were added to the case after this run and are not "
            "covered by it."
        )
    if reparsed:
        changes.append(
            f"{len(reparsed)} source file(s) were re-parsed after this run; event details shown "
            "here are the current parse, and linked events that no longer exist are marked."
        )
    if removed:
        changes.append(f"{len(removed)} source file record(s) used by this run no longer exist.")
    return changes


def _linked_ids(conn: Connection, run_id: str, opts: dict[str, Any]) -> list[str]:
    """IDs of existing events linked to the included findings, in timeline order.

    Only the sort keys are read and sorted here, so large evidence sets need neither
    the full rows in memory nor a large sort inside SQLite.
    """
    allowed = SEVERITIES[SEVERITIES.index(opts["min_severity"]) :]
    linked = (
        select(finding_events.c.event_id)
        .join(findings, findings.c.finding_id == finding_events.c.finding_id)
        .where(
            findings.c.run_id == run_id,
            findings.c.severity.in_(allowed),
            findings.c.status.in_(opts["statuses"]),
        )
    )
    keys = conn.execute(
        select(
            events.c.timestamp_utc,
            events.c.source_file_id,
            events.c.record_index,
            events.c.event_id,
        ).where(events.c.event_id.in_(linked))
    ).all()
    ordered = sorted(keys, key=lambda k: (k[0] is None, k[0] or datetime.min, k[1], k[2]))
    return [k[3] for k in ordered]


def iter_linked_events(conn: Connection, data: ReportData) -> Iterator[dict[str, Any]]:
    """Full rows of data.linked_ids, in that order, 500 at a time."""
    ids = data.linked_ids
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        rows = {
            row["event_id"]: dict(row)
            for row in conn.execute(select(events).where(events.c.event_id.in_(chunk))).mappings()
        }
        yield from (rows[eid] for eid in chunk if eid in rows)


def iter_case_events(conn: Connection, data: ReportData) -> Iterator[dict[str, Any]]:
    """Every event of the run's input files in stable order (DESIGN.md §12.2), placed first.

    Two index-ordered scans instead of one NULLS LAST sort, which on 10M events
    would sort in memory.
    """
    ids = [f["source_file_id"] for f in data.source_files]
    base = select(events).where(
        events.c.case_id == data.case["case_id"], events.c.source_file_id.in_(ids)
    )
    for condition in (events.c.timestamp_utc.is_not(None), events.c.timestamp_utc.is_(None)):
        result = conn.execute(base.where(condition).order_by(*_EVENT_ORDER))
        for partition in result.mappings().partitions(2000):
            yield from (dict(r) for r in partition)


def severity_status_totals(data: ReportData) -> tuple[Counter[str], Counter[str]]:
    by_severity: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    for level, statuses in data.run_counts.items():
        for status, count in statuses.items():
            by_severity[level] += count
            by_status[status] += count
    return by_severity, by_status
