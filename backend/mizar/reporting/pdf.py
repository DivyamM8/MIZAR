"""PDF investigation report (DESIGN.md §13.1), rendered with ReportLab Platypus.

Every piece of text from evidence or the database goes through text.para(),
so log content is drawn as text and never interpreted as markup. ReportLab
loads no external resources.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

from mizar.correlation.index import SESSION_GAP
from mizar.detection.rules import SEVERITIES
from mizar.reporting.data import FINDING_STATUSES, ReportData, severity_status_totals
from mizar.reporting.text import label, para, size, utc
from mizar.versions import EVENT_SCHEMA_VERSION, MIZAR_VERSION, RULE_FORMAT_VERSION

TIMELINE_LIMIT = 1000
ENTITY_LIMIT = 15
MESSAGE_LIMIT = 300
CELL_LIMIT = 300
TOP_FINDINGS = 5

PAGE = A4
MARGIN = 18 * mm
WIDTH = PAGE[0] - 2 * MARGIN
_INK = colors.HexColor("#1f2328")
_MUTED = colors.HexColor("#59636e")
_RULE = colors.HexColor("#d0d7de")
_SHADE = colors.HexColor("#f2f4f6")

_BASE = ParagraphStyle(
    "base", fontName="Helvetica", fontSize=9, leading=12, textColor=_INK, alignment=TA_LEFT
)
STYLES = {
    "body": _BASE,
    "small": ParagraphStyle("small", parent=_BASE, fontSize=7.5, leading=9.5),
    "muted": ParagraphStyle("muted", parent=_BASE, fontSize=8, leading=10.5, textColor=_MUTED),
    "mono": ParagraphStyle("mono", parent=_BASE, fontName="Courier", fontSize=7, leading=8.8),
    "cell_head": ParagraphStyle(
        "cell_head", parent=_BASE, fontName="Helvetica-Bold", fontSize=7.5, leading=9.5
    ),
    "bullet": ParagraphStyle("bullet", parent=_BASE, leftIndent=10, bulletIndent=0),
    "title": ParagraphStyle(
        "title", parent=_BASE, fontName="Helvetica-Bold", fontSize=22, leading=27
    ),
    "subtitle": ParagraphStyle("subtitle", parent=_BASE, fontSize=13, leading=17),
    "h1": ParagraphStyle(
        "h1", parent=_BASE, fontName="Helvetica-Bold", fontSize=14, leading=18, spaceAfter=6
    ),
    "h2": ParagraphStyle(
        "h2",
        parent=_BASE,
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        spaceBefore=8,
        spaceAfter=3,
    ),
    "h3": ParagraphStyle(
        "h3",
        parent=_BASE,
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        spaceBefore=5,
        spaceAfter=1,
    ),
    "marking": ParagraphStyle(
        "marking", parent=_BASE, fontName="Helvetica-Bold", fontSize=12, leading=16
    ),
}
Check = Callable[[], None]


def _p(text: str, style: str = "body") -> Paragraph:
    """A paragraph of trusted markup (already escaped)."""
    return Paragraph(text, STYLES[style])


def _t(value: Any, style: str = "body", limit: int | None = None) -> Paragraph:
    """A paragraph of untrusted text."""
    return Paragraph(para(value, limit), STYLES[style])


def _bullets(items: list[str], untrusted: bool = True) -> list[Flowable]:
    if not items:
        return [_p("None recorded.", "muted")]
    return [
        Paragraph(para(item) if untrusted else item, STYLES["bullet"], bulletText="•")
        for item in items
    ]


def _table(
    rows: list[list[Any]],
    widths: list[float],
    *,
    header: bool = True,
    style: str = "small",
    mono: frozenset[int] = frozenset(),
    key_value: bool = False,
) -> Table:
    """A table of untrusted cell values; strings become escaped paragraphs."""
    cells = []
    for r, row in enumerate(rows):
        out = []
        for c, value in enumerate(row):
            if isinstance(value, Flowable):
                out.append(value)
            elif (header and r == 0) or (key_value and c == 0):
                out.append(_t(value, "cell_head"))
            else:
                out.append(_t(value, "mono" if c in mono else style, CELL_LIMIT))
        cells.append(out)
    table = Table(cells, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), _SHADE))
    if key_value:
        commands.append(("BACKGROUND", (0, 0), (0, -1), _SHADE))
    table.setStyle(TableStyle(commands))
    return table


def _kv(pairs: list[tuple[str, Any]], key_width: float = 42 * mm) -> Table:
    return _table(
        [[k, v] for k, v in pairs],
        [key_width, WIDTH - key_width],
        header=False,
        key_value=True,
        style="body",
    )


def _count(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _filter_statement(data: ReportData) -> str:
    opts = data.options
    parts = []
    if len(opts["statuses"]) < len(FINDING_STATUSES):
        parts.append("statuses " + ", ".join(label(s) for s in opts["statuses"]))
    if opts["min_severity"] != "informational":
        parts.append(f"severity {label(opts['min_severity'])} or higher")
    if not parts:
        return "All findings of the run are included."
    return "Included: findings with " + " and ".join(parts) + "."


# 1. Cover ---------------------------------------------------------------------------


def _cover(data: ReportData) -> list[Flowable]:
    case, run = data.case, data.run
    marking = data.options["marking"].upper()
    marking_note = (
        "Draft: subject to change; not a final record of the investigation."
        if marking == "DRAFT"
        else "Final: issued by the analyst as the record of this analysis."
    )
    return [
        Spacer(1, 30 * mm),
        _p(f"{marking}", "marking"),
        Spacer(1, 4 * mm),
        _p("Investigation report", "title"),
        _t(case["name"], "subtitle"),
        Spacer(1, 10 * mm),
        _kv(
            [
                ("Case reference", case["reference"] or "none"),
                ("Case ID", case["case_id"]),
                ("Analyst", case["analyst_name"]),
                ("Generated", utc(data.generated_at)),
                ("MIZAR version", MIZAR_VERSION),
                ("Analysis run", run["run_id"]),
                ("Run finished", utc(run["finished_at"])),
                ("Run status", label(run["status"])),
                ("Manifest SHA-256", run["manifest_sha256"] or "none"),
                ("Inputs fingerprint", run["inputs_fingerprint"] or "none"),
                ("Report marking", marking_note),
                ("Findings", f"{len(data.findings)} included. {_filter_statement(data)}"),
            ]
        ),
        Spacer(1, 8 * mm),
        _p(
            "This report presents leads produced by automated detection rules over the "
            "evidence listed in section 3. A finding means recorded activity matched a rule; "
            "it is not a conclusion about what happened or who was responsible. Severity, "
            "confidence and evidence strength are rated separately. Statuses and notes reflect "
            "the analyst's review at the time the report was generated. All times are UTC.",
            "muted",
        ),
        PageBreak(),
    ]


# 2. Executive summary ---------------------------------------------------------------


def summary_sentences(data: ReportData) -> list[str]:
    """The executive summary, as plain sentences generated from the data."""
    results = data.results
    by_severity, by_status = severity_status_totals(data)
    total = sum(by_severity.values())
    files = len(data.source_files)
    sentences = [
        f"Analysis run {data.run['run_id']} evaluated "
        f"{_count(results.get('events_evaluated', data.events_total), 'event')} from "
        f"{_count(files, 'source file')}."
    ]
    first, last = data.span
    if first and last:
        sentences.append(f"Events with a reliable UTC time range from {utc(first)} to {utc(last)}.")
    if data.events_unplaced:
        sentences.append(
            f"{_count(data.events_unplaced, 'event')} had no reliable UTC time and could not "
            "be placed on the timeline."
        )
    if total:
        parts = [
            f"{by_severity[s]} {label(s).lower()}" for s in reversed(SEVERITIES) if by_severity[s]
        ]
        sentences.append(
            f"The rules produced {_count(total, 'finding')}: " + ", ".join(parts) + "."
        )
        review = [f"{by_status[s]} {label(s).lower()}" for s in FINDING_STATUSES if by_status[s]]
        sentences.append("Analyst review status: " + ", ".join(review) + ".")
    else:
        sentences.append(
            "The rules produced no findings. This means no rule matched the evidence; it "
            "does not show that no activity of interest took place."
        )
    excluded = data.excluded["by_status"] + data.excluded["by_severity"]
    if excluded:
        sentences.append(
            f"This report covers {len(data.findings)} of them; {excluded} excluded by the "
            f"export filters ({data.excluded['by_status']} by status, "
            f"{data.excluded['by_severity']} below the minimum severity)."
        )
    return sentences


def _limitation_items(data: ReportData) -> list[str]:
    results = data.results
    items = list(data.changed_since_run)
    for error in results.get("rule_errors", []):
        items.append(
            f"Rule {error['rule_id']} failed during the run ({error['error']}) and produced "
            "no findings."
        )
    for gap in results.get("coverage_gaps", []):
        name = gap["filename"] or "Case"
        items.append(f"{name}: {gap['reason']}")
    for rule_id, notes in results.get("rule_notes", {}).items():
        for note in notes.values():
            items.append(f"Rule {rule_id}: {note}")
    hinted = {k: v for k, v in data.timezone_assumptions.items() if k.startswith("analyst_hint:")}
    for assumption, count in sorted(hinted.items()):
        zone = assumption.split(":", 1)[1]
        items.append(
            f"{_count(count, 'event')} were converted to UTC using the analyst's timezone hint "
            f"{zone}; the logs themselves did not record an offset."
        )
    return items


def _summary(data: ReportData) -> list[Flowable]:
    story: list[Flowable] = [_p("2. Executive summary", "h1")]
    story += [_t(s) for s in summary_sentences(data)]
    story.append(_p("Findings in the run by severity and status", "h2"))
    header = ["Severity", *[label(s) for s in FINDING_STATUSES], "Total"]
    rows: list[list[Any]] = [header]
    for level in reversed(SEVERITIES):
        counts = data.run_counts[level]
        rows.append(
            [label(level), *[str(counts[s]) for s in FINDING_STATUSES], str(sum(counts.values()))]
        )
    story.append(_table(rows, [30 * mm] + [(WIDTH - 30 * mm) / 6] * 6))
    if data.findings:
        story.append(_p("Highest-priority findings in this report", "h2"))
        top = [["Finding", "Severity", "Confidence", "Evidence", "Status", "Title"]]
        for finding in data.findings[:TOP_FINDINGS]:
            top.append(
                [
                    data.short_id(finding["finding_id"]),
                    label(finding["severity"]),
                    label(finding["confidence"]),
                    label(finding["evidence_strength"]),
                    label(finding["status"]),
                    finding["title"],
                ]
            )
        story.append(_table(top, [16 * mm, 18 * mm, 19 * mm, 22 * mm, 22 * mm, WIDTH - 97 * mm]))
        story.append(
            _p(
                "Priority order: severity, then confidence, then evidence strength, then first "
                f"observed time. Finding numbers refer to run {para(data.run['run_id'])}.",
                "muted",
            )
        )
    limits = _limitation_items(data)
    story.append(_p("Key limitations", "h2"))
    story += _bullets(limits[:6] or ["No coverage gaps, rule errors or timezone hints recorded."])
    if len(limits) > 6:
        story.append(_p(f"{len(limits) - 6} more in section 8.", "muted"))
    story.append(PageBreak())
    return story


# 3. Scope and evidence --------------------------------------------------------------


def _scope(data: ReportData) -> list[Flowable]:
    story: list[Flowable] = [
        _p("3. Scope and evidence", "h1"),
        _p(
            "Source files analyzed by the run, as recorded in its manifest. Every file was "
            "verified against its SHA-256 hash before the rules ran; the original bytes are "
            "kept unmodified in the evidence store.",
            "muted",
        ),
        Spacer(1, 2 * mm),
    ]
    rows: list[list[Any]] = [
        ["#", "File", "Size", "Format / parser", "Ingested", "Records", "Integrity"]
    ]
    for f in data.source_files:
        records = (
            f"{f['records_total']} total, {f['records_partial']} partial, "
            f"{f['records_unparsed']} unparsed"
            if f["records_total"] is not None
            else "not parsed"
        )
        parser = (
            f"{f['format'] or 'unknown'}\n{f['parser_name']} {f['parser_version']}"
            if f["parser_name"]
            else (f["format"] or f["container_type"] or f["status"])
        )
        name = Paragraph(
            para(f["filename"]) + "<br/>" + f'<font name="Courier" size="6.5">'
            f"{para(f['sha256'])}</font>",
            STYLES["small"],
        )
        rows.append(
            [
                str(f["sequence"] or ""),
                name,
                size(f["size_bytes"]),
                parser,
                utc(f["ingestion_time"]),
                records,
                label(f["integrity_status"])
                + (
                    "\n" + utc(datetime.fromisoformat(f["verified_at"]).replace(microsecond=0))
                    if f.get("verified_at")
                    else ""
                ),
            ]
        )
    story.append(
        _table(rows, [7 * mm, 58 * mm, 15 * mm, 26 * mm, 20 * mm, 22 * mm, WIDTH - 148 * mm])
    )

    gaps = data.results.get("coverage_gaps", [])
    story.append(_p("Coverage gaps", "h2"))
    story += _bullets(
        [f"{g['filename'] or 'Case'}: {g['reason']}" for g in gaps]
        or ["No coverage gaps were recorded by the run."]
    )
    story.append(_p("Timestamp basis", "h2"))
    zones = [["How the UTC time was determined", "Events"]]
    meanings = {
        "explicit": "The record states its UTC offset",
        "format_defined_utc": "The format defines times as UTC",
        "none": "No reliable UTC time (not placed on the timeline)",
    }
    for assumption, count in data.timezone_assumptions.items():
        if assumption.startswith("analyst_hint:"):
            text = f"Analyst timezone hint {assumption.split(':', 1)[1]}"
        else:
            text = meanings.get(assumption, assumption)
        zones.append([text, str(count)])
    story.append(_table(zones, [WIDTH - 30 * mm, 30 * mm]))
    story.append(PageBreak())
    return story


# 4. Methodology ---------------------------------------------------------------------


def _methodology(data: ReportData) -> list[Flowable]:
    manifest = data.manifest
    config = manifest.get("config", {})
    overrides = data.run.get("overrides") or {}
    rules = _count(len(manifest.get("rules", [])), "detection rule")
    rule_format = manifest.get("rule_format_version", RULE_FORMAT_VERSION)
    schema = manifest.get("event_schema_version", EVENT_SCHEMA_VERSION)
    cap = config.get("evidence_cap_per_finding", "a capped number of")
    gap_hours = int(SESSION_GAP.total_seconds() // 3600)
    story: list[Flowable] = [_p("4. Methodology", "h1")]
    story.append(
        _t(
            f"The run applied {rules} (rule format {rule_format}) to events normalized to "
            f"event schema {schema}. Each rule's version and file hash and every parameter "
            "value are listed in the appendix."
        )
    )
    story.append(_p("Parameter changes for this run", "h2"))
    if overrides:
        rows = [["Rule", "Parameter", "Value used"]]
        for rule_id, params in sorted(overrides.items()):
            for name, value in sorted(params.items()):
                rows.append([rule_id, name, str(value)])
        story.append(_table(rows, [30 * mm, 50 * mm, WIDTH - 80 * mm]))
    else:
        story.append(_p("None: every rule used its default thresholds.", "muted"))
    story.append(_p("Processing policies", "h2"))
    story += _bullets(
        [
            "Times: a UTC time is assigned only from an explicit offset in the record, a format "
            "that defines UTC, or a timezone hint supplied by the analyst. Ambiguous or "
            "nonexistent local times (daylight-saving changes) are left without a UTC time rather "
            "than guessed. Clock differences between hosts are not corrected.",
            "Duplicates: the same record collected in several files is kept in every file and "
            "grouped; rules count such a group "
            + ("once." if config.get("count_duplicates_once", True) else "once per copy."),
            f"Evidence: each finding links up to {cap} supporting events; when more matched, "
            "the finding records the full count and that "
            "the list is truncated.",
            "Correlation: sessions group events sharing host and session ID, split after a gap of "
            f"{gap_hours} hours. Process links are stored only where "
            "the log documents them (Sysmon ProcessGuid). Related activity by shared IP, user or "
            "host is shown as shared attributes, not as cause and effect.",
            "Ratings: severity estimates potential impact if the activity is what the rule "
            "describes; confidence estimates how likely that interpretation is; evidence strength "
            "describes how directly the records show it (direct, corroborated, circumstantial, "
            "inferred). Each finding lists the reasons for its ratings.",
        ],
        untrusted=False,
    )
    story.append(PageBreak())
    return story


# 5. Findings ------------------------------------------------------------------------


def _entity_text(entities: dict[str, Any]) -> str:
    parts = []
    for key, value in sorted(entities.items()):
        shown = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
        parts.append(f"{key}: {shown}")
    return "; ".join(parts) or "none"


def _observed(observed: dict[str, Any]) -> list[str]:
    items = [
        f"{observed.get('event_count', 0)} matching events"
        + (
            f" ({observed['weighted_count']} counting duplicate groups once)"
            if observed.get("weighted_count") not in (None, observed.get("event_count"))
            else ""
        )
        + f"; {observed.get('evidence_events_linked', 0)} linked as evidence"
        + (" (list truncated at the cap)" if observed.get("evidence_truncated") else "")
        + "."
    ]
    for name, values in sorted((observed.get("top_values") or {}).items()):
        distinct = (observed.get("distinct") or {}).get(name, len(values))
        shown = ", ".join(f"{v} ({n})" for v, n in values)
        items.append(f"{name}: {distinct} distinct; most frequent {shown}")
    skip = {
        "event_count",
        "weighted_count",
        "evidence_events_linked",
        "evidence_truncated",
        "distinct",
        "top_values",
        "sample_event_ids",
        "params",
        "chain",
    }
    for key, value in sorted(observed.items()):
        if key not in skip and isinstance(value, int | str | float):
            items.append(f"{key.replace('_', ' ')}: {value}")
    if observed.get("params"):
        items.append(
            "Thresholds: " + ", ".join(f"{k}={v}" for k, v in sorted(observed["params"].items()))
        )
    return items


def _evidence_table(data: ReportData, finding: dict[str, Any]) -> list[Flowable]:
    limit = data.options["evidence_limit"]
    linked = finding["evidence"]
    rows: list[list[Any]] = [
        ["Time (UTC) / original", "Host / user", "Network", "Event / role", "Message"]
    ]
    for event_id, role in linked[:limit]:
        event = data.events.get(event_id)
        if event is None:
            rows.append(
                [
                    "",
                    "",
                    "",
                    role,
                    f"Event {event_id} is no longer in the case "
                    "(its file was re-parsed or removed).",
                ]
            )
            continue
        network = _network(event)
        kind = " ".join(
            x for x in (event["event_type"], event["event_outcome"], event["event_code"]) if x
        )
        rows.append(
            [
                f"{utc(event['timestamp_utc'])}\n{event['timestamp_original'] or ''}",
                f"{event['hostname'] or ''}\n{event['username'] or ''}",
                network,
                Paragraph(
                    para(kind) + f'<br/><font color="#59636e">{para(role)}</font>', STYLES["small"]
                ),
                _t(event["message"] or "", "small", MESSAGE_LIMIT),
            ]
        )
    story: list[Flowable] = [_table(rows, [33 * mm, 30 * mm, 32 * mm, 30 * mm, WIDTH - 125 * mm])]
    if len(linked) > limit:
        story.append(
            _p(
                f"Showing {limit} of {len(linked)} linked events. The full list, with each "
                "original record, is in the JSON export.",
                "muted",
            )
        )
    return story


def _finding(data: ReportData, finding: dict[str, Any]) -> list[Flowable]:
    short = data.short_id(finding["finding_id"])
    files = finding["source_files"]
    head = [
        _p(f"{short} · {para(finding['title'])}", "h2"),
        _kv(
            [
                ("Finding ID", finding["finding_id"]),
                ("Rule", f"{finding['rule_id']} version {finding['rule_version']}"),
                ("Severity", label(finding["severity"])),
                ("Confidence", label(finding["confidence"])),
                ("Evidence strength", label(finding["evidence_strength"])),
                (
                    "Status",
                    label(finding["status"])
                    + (
                        f" (set by {finding['updated_by']} at {utc(finding['updated_at'])})"
                        if finding["updated_at"]
                        else ""
                    )
                    + (
                        " (carried over from the previous run)"
                        if finding["status_carried_from"]
                        else ""
                    ),
                ),
                ("ATT&CK", ", ".join(finding["attack_techniques"]) or "none"),
                ("First observed", utc(finding["first_observed_utc"])),
                ("Last observed", utc(finding["last_observed_utc"])),
                ("Entities", _entity_text(finding["entities"])),
            ],
            key_width=32 * mm,
        ),
    ]
    story: list[Flowable] = [CondPageBreak(60 * mm), KeepTogether(head)]
    sections: list[tuple[str, list[Flowable]]] = [
        ("Description", [_t(finding["description"])]),
        ("Severity rationale", _bullets(finding["severity_rationale"])),
        ("Confidence rationale", _bullets(finding["confidence_rationale"])),
        ("Observed evidence", _bullets(_observed(finding["observed_evidence"]))),
        ("Interpretation", [_t(finding["interpretation"])]),
        ("Alternative explanations", _bullets(finding["alternative_explanations"])),
        ("Verification steps", _bullets(finding["verification_steps"])),
        ("Source files", _bullets([f"{f['filename']} (SHA-256 {f['sha256']})" for f in files])),
    ]
    if finding["related_finding_ids"]:
        sections.append(
            (
                "Related findings",
                [_t(", ".join(data.short_id(r) for r in finding["related_finding_ids"]))],
            )
        )
    sections.append(
        (
            "Analyst notes",
            [_t(finding["analyst_notes"])] if finding["analyst_notes"] else [_p("None.", "muted")],
        )
    )
    for title, body in sections:
        story.append(KeepTogether([_p(title, "h3"), *body[:1]]))
        story += body[1:]
    story.append(_p("Supporting events", "h3"))
    story += _evidence_table(data, finding)
    story.append(Spacer(1, 6 * mm))
    return story


def _findings(data: ReportData, check: Check) -> list[Flowable]:
    story: list[Flowable] = [_p("5. Findings", "h1")]
    if not data.findings:
        story.append(_p("No findings are included in this report.", "muted"))
    for finding in data.findings:
        check()
        story += _finding(data, finding)
    story.append(PageBreak())
    return story


# 6-7. Timeline and entities ---------------------------------------------------------


def _network(event: dict[str, Any]) -> str:
    if not (event["source_ip"] or event["destination_ip"]):
        return ""
    src = event["source_ip"] or "?"
    if event["source_port"] is not None:
        src += f":{event['source_port']}"
    dst = event["destination_ip"] or ""
    if event["destination_port"] is not None:
        dst += f":{event['destination_port']}"
    return f"{src} -> {dst}" if dst else src


def _timeline(data: ReportData) -> list[Flowable]:
    limit = data.options["evidence_limit"]
    shown = data.timeline(per_finding=limit)
    every = len(data.timeline())
    story: list[Flowable] = [
        _p("6. Timeline of finding-related events", "h1"),
        _p(
            f"The supporting events shown in section 5 (up to {limit} per finding), in UTC order. "
            "Events without a reliable UTC time are listed last.",
            "muted",
        ),
        Spacer(1, 2 * mm),
    ]
    rows: list[list[Any]] = [
        ["Time (UTC)", "Host / user", "Event / network", "Message", "Findings"]
    ]
    for event in shown[:TIMELINE_LIMIT]:
        rows.append(
            [
                utc(event["timestamp_utc"])
                + ("" if event["timestamp_utc"] else f"\n{event['timestamp_original'] or ''}"),
                f"{event['hostname'] or ''}\n{event['username'] or ''}",
                f"{event['event_type'] or ''}\n{_network(event)}",
                _t(event["message"] or "", "small", MESSAGE_LIMIT),
                ", ".join(data.short_id(f) for f in event["finding_ids"]),
            ]
        )
    if len(rows) == 1:
        story.append(_p("No events are linked to the included findings.", "muted"))
    else:
        story.append(_table(rows, [33 * mm, 28 * mm, 34 * mm, WIDTH - 115 * mm, 20 * mm]))
    if every > min(len(shown), TIMELINE_LIMIT):
        story.append(
            _p(
                f"Showing {min(len(shown), TIMELINE_LIMIT)} of the {every} events linked to the "
                "included findings; the JSON and CSV exports contain all of them.",
                "muted",
            )
        )
    story.append(PageBreak())
    return story


def _entities(data: ReportData) -> list[Flowable]:
    story: list[Flowable] = [
        _p("7. Entities in findings", "h1"),
        _p(
            "Hosts, users and IP addresses named by the included findings. Appearing here "
            "means an entity is part of matched activity, not that it acted with intent.",
            "muted",
        ),
    ]
    titles = {"host": "Hosts", "user": "Users", "ip": "IP addresses"}
    for kind, entries in data.entities().items():
        story.append(_p(titles[kind], "h2"))
        if not entries:
            story.append(_p("None.", "muted"))
            continue
        rows = [["Value", "Findings", "Highest severity", "Finding numbers"]]
        for entry in entries[:ENTITY_LIMIT]:
            rows.append(
                [
                    entry["value"],
                    str(len(entry["finding_ids"])),
                    label(entry["max_severity"]),
                    ", ".join(data.short_id(f) for f in entry["finding_ids"]),
                ]
            )
        story.append(_table(rows, [50 * mm, 18 * mm, 26 * mm, WIDTH - 94 * mm]))
        if len(entries) > ENTITY_LIMIT:
            story.append(_p(f"{len(entries) - ENTITY_LIMIT} more not shown.", "muted"))
    story.append(PageBreak())
    return story


# 8-9. Limitations and appendix ------------------------------------------------------


def _limitations(data: ReportData) -> list[Flowable]:
    standing = [
        "Findings come from rules matching recorded events. Activity that was not logged, "
        "logs that were not collected, and techniques no rule covers do not appear.",
        "Clock differences between hosts are not corrected; ordering across hosts relies on "
        "each host's clock.",
        "Severity and confidence are rule-based estimates, explained per finding, and need "
        "analyst verification.",
        "Characters no report font can draw (for example Chinese, Japanese and Korean), "
        "right-to-left scripts, which this PDF cannot lay out in reading order, and invisible "
        "formatting characters are shown as \\u{NNNN} escapes, and control characters as "
        "\\xNN; the JSON export has the exact text.",
        f"Long messages are shortened to {MESSAGE_LIMIT} characters and evidence lists to "
        f"{data.options['evidence_limit']} events per finding in this PDF.",
    ]
    return [
        _p("8. Limitations and assumptions", "h1"),
        _p("Specific to this case and run", "h2"),
        *_bullets(_limitation_items(data) or ["None recorded."]),
        _p("Standing limitations", "h2"),
        *_bullets(standing),
        PageBreak(),
    ]


def _appendix(data: ReportData) -> list[Flowable]:
    manifest = data.manifest
    run = data.run
    story: list[Flowable] = [
        _p("9. Appendix: run manifest", "h1"),
        _kv(
            [
                ("Run ID", run["run_id"]),
                ("Triggered by", run["triggered_by"]),
                ("Started", utc(run["started_at"])),
                ("Finished", utc(run["finished_at"])),
                ("MIZAR version", manifest.get("mizar_version", "")),
                ("Event schema", manifest.get("event_schema_version", "")),
                ("Rule format", manifest.get("rule_format_version", "")),
                ("Manifest SHA-256", run["manifest_sha256"] or ""),
                ("Inputs fingerprint", run["inputs_fingerprint"] or ""),
                ("Configuration", json.dumps(manifest.get("config", {}), sort_keys=True)),
            ],
            key_width=36 * mm,
        ),
        _p("Rules", "h2"),
    ]
    params = manifest.get("params", {})
    rows: list[list[Any]] = [["Rule", "Version", "Rule file SHA-256", "Parameters"]]
    for rule in manifest.get("rules", []):
        values = params.get(rule["rule_id"], {})
        rows.append(
            [
                rule["rule_id"],
                rule["rule_version"],
                rule["rule_file_sha256"],
                ", ".join(f"{k}={v}" for k, v in sorted(values.items())) or "none",
            ]
        )
    story.append(_table(rows, [18 * mm, 14 * mm, 62 * mm, WIDTH - 94 * mm], mono=frozenset({2})))
    story.append(
        _p(
            "The complete manifest, including every input and its parse result, is "
            "in the JSON export.",
            "muted",
        )
    )
    return story


# Page furniture ---------------------------------------------------------------------


def _canvas_class(footer: str, marking: str) -> type[canvas.Canvas]:
    class ReportCanvas(canvas.Canvas):  # type: ignore[misc]
        """Draws the footer with "Page X of Y" after all pages are known."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._pages: list[dict[str, Any]] = []

        def showPage(self) -> None:
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total: int) -> None:
            width, height = PAGE
            self.saveState()
            # The only branding: a small, low-contrast name in each corner (DESIGN.md D14).
            self.setFont("Helvetica-Bold", 7)
            self.setFillColor(colors.Color(0.55, 0.58, 0.62, alpha=0.45))
            low, high = 8 * mm, height - 10 * mm
            self.drawString(MARGIN, high, "MIZAR")
            self.drawRightString(width - MARGIN, high, "MIZAR")
            self.drawString(MARGIN, low, "MIZAR")
            self.drawRightString(width - MARGIN, low, "MIZAR")
            self.setFillColor(_MUTED)
            self.setFont("Helvetica", 7)
            self.drawCentredString(width / 2, high, marking)
            self.drawCentredString(width / 2, low, f"{footer} · Page {self._pageNumber} of {total}")
            self.restoreState()

    return ReportCanvas


def render_pdf(path: Path, data: ReportData, check: Check) -> dict[str, int]:
    run_id = data.run["run_id"]
    case_id = data.case["case_id"]
    marking = data.options["marking"].upper()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=PAGE,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=f"Investigation report: {data.case['name']}",
        author=data.case["analyst_name"],
        subject=f"Case {case_id}, analysis run {run_id}",
        creator=f"MIZAR {MIZAR_VERSION}",
        producer=f"MIZAR {MIZAR_VERSION}",
    )
    story: list[Flowable] = []
    story += _cover(data)
    story += _summary(data)
    story += _scope(data)
    story += _methodology(data)
    story += _findings(data, check)
    check()
    story += _timeline(data)
    story += _entities(data)
    story += _limitations(data)
    story += _appendix(data)
    check()
    doc.build(story, canvasmaker=_canvas_class(f"Case {case_id} · Run {run_id}", marking))
    return {"findings": len(data.findings), "pages": doc.page}
