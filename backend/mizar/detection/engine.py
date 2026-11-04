"""Detection engine: evaluates rules over a case's events (DESIGN.md §9, §11).

Each rule streams only the events its filter can match (SQL prefilter on
indexed columns), in timeline order, and is checked event by event in
Python. Rules produce Candidates: one per rule per grouping key, holding the
evidence events. Candidates become findings in build_finding().

Time-based rules (threshold, sequence, first_seen, correlation) can only use
events with a reliable UTC time; events without one are counted and reported,
never placed by guesswork.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, Connection, literal_column, select

from mizar.db.tables import event_group_members, event_groups, events
from mizar.detection.conditions import Event, compile_filter, field_getter, sql_prefilter
from mizar.detection.rules import CONFIDENCES, SEVERITIES, Rule

EVIDENCE_CAP = 10_000
_CORRELATION_EVIDENCE_PER_FINDING = 50
_FIRST_SEEN_EVIDENCE = 20
_SUMMARY_FIELDS = ("hostname", "username", "source_ip", "destination_ip", "destination_port")
_TOP_VALUES = 5
_LOADED_COLUMNS = [
    c for c in events.columns if c.name not in ("extra", "original_record_reference")
]
_CASE_NOT_INDEXED: ColumnElement[str] = literal_column("+events.case_id")
_PLACEHOLDER = re.compile(
    r"\{([a-z][a-z_]*(?:\.[a-z][a-z_]*)?(?:\|[a-z][a-z_]*(?:\.[a-z][a-z_]*)?)*)\}"
)


@dataclass(eq=False)
class Candidate:
    rule: Rule
    key: dict[str, Any]
    events: list[tuple[Event, str]] = field(default_factory=list)
    event_count: int = 0
    weighted_count: int = 0
    facts: dict[str, Any] = field(default_factory=dict)
    related: list[Candidate] = field(default_factory=list)
    _seen: set[Token] = field(default_factory=set)

    def add(self, event: Event, role: str, weight: int = 1) -> None:
        if event["event_id"] in self._seen:
            return
        self._seen.add(event["event_id"])
        self.event_count += 1
        self.weighted_count += weight
        if len(self.events) < EVIDENCE_CAP:
            self.events.append((event, role))

    def timestamps(self) -> list[datetime]:
        stamps = [e["timestamp_utc"] for e, _ in self.events if e["timestamp_utc"] is not None]
        for other in self.related:
            stamps.extend(other.timestamps())
        return stamps

    def entity(self, name: str) -> Any:
        """The candidate's single value for a field: its key, else a unique evidence value."""
        if name in self.key:
            return self.key[name]
        get = field_getter(name)
        values = {get(e) for e, _ in self.events} - {None}
        return next(iter(values)) if len(values) == 1 else None


Token = tuple[Any, ...]


def _token(key: dict[str, Any]) -> Token:
    """Hashable form of a grouping key (list values, e.g. paths, become tuples)."""
    return tuple(tuple(v) if isinstance(v, list) else v for v in key.values())


def _weight(event: Event) -> int:
    """rsyslog 'message repeated N times' lines stand for N occurrences."""
    extra = event.get("extra") or {}
    repeated = extra.get("repeat_count") if isinstance(extra, dict) else None
    return repeated if isinstance(repeated, int) and repeated > 0 else 1


class Detector:
    def __init__(self, conn: Connection, case_id: str, params: dict[str, dict[str, Any]]) -> None:
        self.conn = conn
        self.case_id = case_id
        self.params = params
        self.notes: dict[str, dict[str, Any]] = defaultdict(dict)
        self.duplicate_of = self._duplicate_groups()

    def _duplicate_groups(self) -> dict[str, str]:
        rows = self.conn.execute(
            select(event_group_members.c.event_id, event_group_members.c.group_id)
            .join(event_groups, event_groups.c.group_id == event_group_members.c.group_id)
            .where(event_groups.c.case_id == self.case_id, event_groups.c.group_type == "duplicate")
        )
        return {event_id: group_id for event_id, group_id in rows}

    def _param(self, rule: Rule, name: str) -> Any:
        return rule.params[name].native(self.params[rule.id][name])

    def _stream(self, rule: Rule, spec: Any) -> Iterator[Event]:
        prefilter = sql_prefilter(spec)
        case_column = _CASE_NOT_INDEXED if prefilter else events.c.case_id
        columns = [*_LOADED_COLUMNS, events.c.extra]
        query = select(*columns).where(case_column == self.case_id, *prefilter)
        applies_to = rule.spec.get("applies_to")
        if applies_to:
            query = query.where(events.c.source_type.in_(applies_to))
        query = query.order_by(
            events.c.timestamp_utc.is_(None),
            events.c.timestamp_utc,
            events.c.source_file_id,
            events.c.record_index,
        )
        for row in self.conn.execute(query.execution_options(yield_per=5000)).mappings():
            yield dict(row)

    def _note_without_utc(self, rule: Rule, count: int) -> None:
        if count:
            self.notes[rule.id]["events_without_utc_skipped"] = count

    # --- rule types ------------------------------------------------------------------

    def run(self, rule: Rule, base: dict[str, list[Candidate]] | None = None) -> list[Candidate]:
        if rule.type == "match":
            return self._match(rule)
        if rule.type == "threshold":
            return self._threshold(rule)
        if rule.type == "sequence":
            return self._sequence(rule)
        if rule.type == "first_seen":
            return self._first_seen(rule)
        return self._correlation(rule, base or {})

    def _group_key(self, rule: Rule, event: Event, fields: list[str]) -> dict[str, Any]:
        return {name: field_getter(name)(event) for name in fields}

    def _match(self, rule: Rule) -> list[Candidate]:
        assert rule.predicate is not None
        group_by = rule.spec.get("group_by", [])
        groups: dict[Token, Candidate] = {}
        for event in self._stream(rule, rule.spec["filter"]):
            if not rule.predicate(event):
                continue
            key = (
                self._group_key(rule, event, group_by)
                if group_by
                else {"event_id": event["event_id"]}
            )
            token = _token(key)
            candidate = groups.setdefault(token, Candidate(rule, key))
            candidate.add(event, "trigger", _weight(event))
        return list(groups.values())

    def _threshold(self, rule: Rule) -> list[Candidate]:
        assert rule.predicate is not None
        block = rule.spec["threshold"]
        need = self._param(rule, block["count"])
        window: timedelta = self._param(rule, block["window"])
        distinct = field_getter(block["distinct"]) if "distinct" in block else None
        once = block.get("count_duplicates_once", True)
        group_by = rule.spec["group_by"]
        series: dict[Token, tuple[dict[str, Any], list[tuple[datetime, int, Any, Event]]]] = {}
        seen_duplicates: dict[Token, set[str]] = defaultdict(set)
        without_utc = 0
        for event in self._stream(rule, rule.spec["filter"]):
            if not rule.predicate(event):
                continue
            if event["timestamp_utc"] is None:
                without_utc += 1
                continue
            key = self._group_key(rule, event, group_by)
            token = _token(key)
            duplicate = self.duplicate_of.get(event["event_id"])
            if once and duplicate is not None:
                if duplicate in seen_duplicates[token]:
                    continue  # the same record collected twice counts once
                seen_duplicates[token].add(duplicate)
            value = distinct(event) if distinct else None
            series.setdefault(token, (key, []))[1].append(
                (event["timestamp_utc"], _weight(event), value, event)
            )
        self._note_without_utc(rule, without_utc)

        candidates = []
        for key, items in series.values():
            bursts = _bursts(items, need, window, distinct is not None)
            if not bursts:
                continue
            candidate = Candidate(rule, key)
            for start, end in bursts:
                for _, weight, _, event in items[start : end + 1]:
                    candidate.add(event, "trigger", weight)
            candidate.facts["bursts"] = [
                {
                    "start_utc": _iso(items[start][0]),
                    "end_utc": _iso(items[end][0]),
                    "count": sum(w for _, w, _, _ in items[start : end + 1]),
                    **(
                        {"distinct": len({v for _, _, v, _ in items[start : end + 1]} - {None})}
                        if distinct
                        else {}
                    ),
                }
                for start, end in bursts
            ]
            candidates.append(candidate)
        return candidates

    def _sequence(self, rule: Rule) -> list[Candidate]:
        block = rule.spec["sequence"]
        first, then = block["first"], block["then"]
        first_test = rule.step_predicates[first["name"]]
        then_test = rule.step_predicates[then["name"]]
        window: timedelta = self._param(rule, block["window"])
        need = self._param(rule, first["min_count"])
        join = block["join"]
        group_by = rule.spec.get("group_by", join)
        combined = {"any": [first["filter"], then["filter"]]}
        pending: dict[Token, deque[tuple[datetime, int, Event]]] = defaultdict(deque)
        groups: dict[Token, Candidate] = {}
        without_utc = 0
        for event in self._stream(rule, combined):
            is_first, is_then = first_test(event), then_test(event)
            if not (is_first or is_then):
                continue
            stamp = event["timestamp_utc"]
            if stamp is None:
                without_utc += 1
                continue
            join_key = self._group_key(rule, event, join)
            if any(value is None for value in join_key.values()):
                continue
            token = _token(join_key)
            earlier = pending[token]
            if is_then:
                while earlier and stamp - earlier[0][0] > window:
                    earlier.popleft()
                total = sum(weight for _, weight, _ in earlier)
                if total >= need:
                    key = self._group_key(rule, event, group_by)
                    group = _token(key)
                    candidate = groups.setdefault(group, Candidate(rule, key))
                    for _, weight, prior in earlier:
                        candidate.add(prior, first["name"], weight)
                    candidate.add(event, then["name"])
                    candidate.facts.setdefault("matches", []).append(
                        {
                            "event_id": event["event_id"],
                            "at_utc": _iso(stamp),
                            f"{first['name']}_count": total,
                        }
                    )
            if is_first:
                earlier.append((stamp, _weight(event), event))
        self._note_without_utc(rule, without_utc)
        for candidate in groups.values():
            counts = [m[f"{first['name']}_count"] for m in candidate.facts["matches"]]
            candidate.facts[f"{first['name']}_count"] = max(counts)
        return list(groups.values())

    def _first_seen(self, rule: Rule) -> list[Candidate]:
        assert rule.predicate is not None
        keys = rule.spec["first_seen"]["key"]
        baseline: timedelta = self._param(rule, rule.spec["first_seen"]["baseline"])
        start: datetime | None = None
        last: datetime | None = None
        seen: set[Token] = set()
        found: dict[Token, Candidate] = {}
        without_utc = 0
        for event in self._stream(rule, rule.spec["filter"]):
            if not rule.predicate(event):
                continue
            stamp = event["timestamp_utc"]
            if stamp is None:
                without_utc += 1
                continue
            start = start or stamp
            last = stamp
            key = self._group_key(rule, event, keys)
            if any(value is None for value in key.values()):
                continue
            token = _token(key)
            if token in found:
                candidate = found[token]
                if len(candidate.events) < _FIRST_SEEN_EVIDENCE:
                    candidate.add(event, "later_occurrence")
                else:
                    candidate.event_count += 1
                continue
            if token in seen:
                continue
            seen.add(token)
            if stamp > start + baseline:
                candidate = Candidate(rule, key)
                candidate.add(event, "first_occurrence")
                candidate.facts["baseline_end_utc"] = _iso(start + baseline)
                found[token] = candidate
        self._note_without_utc(rule, without_utc)
        if start is not None and last is not None and last - start <= baseline:
            self.notes[rule.id]["insufficient_baseline"] = (
                f"The matching events span {human_duration(last - start)}, not more than the "
                f"{human_duration(baseline)} baseline, so nothing can be first seen after it."
            )
        return list(found.values())

    def _correlation(self, rule: Rule, base: dict[str, list[Candidate]]) -> list[Candidate]:
        block = rule.spec["correlation"]
        join = block["join"]
        window: timedelta = self._param(rule, block["window"])

        def items(step: dict[str, Any]) -> list[tuple[datetime, datetime, Any, Candidate | Event]]:
            found: list[tuple[datetime, datetime, Any, Candidate | Event]] = []
            if "findings" in step:
                for rule_id in step["findings"]:
                    for candidate in base.get(rule_id, []):
                        stamps = candidate.timestamps()
                        value = candidate.entity(join)
                        if stamps and value is not None:
                            found.append((min(stamps), max(stamps), value, candidate))
                return found
            test = compile_filter(step["events"])
            get = field_getter(join)
            for event in self._stream(rule, step["events"]):
                if test(event) and event["timestamp_utc"] is not None and get(event) is not None:
                    found.append(
                        (event["timestamp_utc"], event["timestamp_utc"], get(event), event)
                    )
            return found

        firsts, thens = items(block["first"]), items(block["then"])
        groups: dict[Token, Candidate] = {}
        for f_start, f_end, value, f_item in firsts:
            for t_start, _, t_value, t_item in thens:
                if t_value != value or not (f_start <= t_start <= f_end + window):
                    continue
                token = _token({join: value})
                candidate = groups.setdefault(token, Candidate(rule, {join: value}))
                for step, item in ((block["first"], f_item), (block["then"], t_item)):
                    if isinstance(item, Candidate):
                        if all(item is not known for known in candidate.related):
                            candidate.related.append(item)
                            for event, _ in item.events[:_CORRELATION_EVIDENCE_PER_FINDING]:
                                candidate.add(event, f"{step['name']}:{item.rule.id}")
                    else:
                        candidate.add(item, step["name"])
        for candidate in groups.values():
            candidate.facts["chain"] = [
                {"rule_id": other.rule.id, "key": other.key} for other in candidate.related
            ]
        return list(groups.values())


def human_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    parts: list[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size or (unit == "s" and not parts):
            parts.append(f"{seconds // size}{unit}")
            seconds %= size
    return " ".join(parts)


def _bursts(
    items: list[tuple[datetime, int, Any, Event]], need: int, window: timedelta, distinct: bool
) -> list[tuple[int, int]]:
    """Index ranges where the windowed count (or distinct count) reaches `need`."""
    bursts: list[tuple[int, int]] = []
    left = 0
    total = 0
    values: Counter[Any] = Counter()
    for right, (stamp, weight, value, _) in enumerate(items):
        total += weight
        if distinct and value is not None:
            values[value] += 1
        while stamp - items[left][0] > window:
            _, old_weight, old_value, _ = items[left]
            total -= old_weight
            if distinct and old_value is not None:
                values[old_value] -= 1
                if not values[old_value]:
                    del values[old_value]
            left += 1
        if (len(values) if distinct else total) >= need:
            if bursts and left <= bursts[-1][1]:
                bursts[-1] = (bursts[-1][0], right)
            else:
                bursts.append((left, right))
    return bursts


# --- findings --------------------------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def fingerprint(candidate: Candidate) -> str:
    major = candidate.rule.version.split(".", 1)[0]
    key = json.dumps(candidate.key, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{candidate.rule.id}|{major}|{key}".encode()).hexdigest()


def _condition_holds(when: dict[str, Any], candidate: Candidate, evidence: list[Event]) -> bool:
    checks = []
    if "count_gte" in when:
        checks.append(candidate.weighted_count >= when["count_gte"])
    if "distinct_gte" in when:
        spec = when["distinct_gte"]
        get = field_getter(spec["field"])
        checks.append(len({get(e) for e in evidence} - {None}) >= spec["value"])
    if "any_event" in when:
        test = compile_filter(when["any_event"])
        checks.append(any(test(e) for e in evidence))
    if "all_events" in when:
        test = compile_filter(when["all_events"])
        checks.append(bool(evidence) and all(test(e) for e in evidence))
    if "all_events_parsed" in when:
        parsed = all(e["parsing_status"] == "parsed" for e in evidence)
        checks.append(parsed is bool(when["all_events_parsed"]))
    if "includes_rules" in when:
        chained = {other.rule.id for other in candidate.related}
        checks.append(set(when["includes_rules"]) <= chained)
    return all(checks)


def _rate(
    candidate: Candidate,
    evidence: list[Event],
    kind: str,
    levels: tuple[str, ...],
    automatic: list[tuple[int, str]],
) -> tuple[str, list[str]]:
    spec = candidate.rule.spec[kind]
    level = levels.index(spec["base"])
    ceiling = levels.index("high")
    rationale = [f"Base {kind} {spec['base']}: {spec['reason']}"]
    adjustments = [
        (modifier, modifier["reason"])
        for modifier in spec.get("modifiers", [])
        if _condition_holds(modifier["when"], candidate, evidence)
    ]
    for modifier, reason in adjustments:
        if "set" in modifier:
            new = levels.index(modifier["set"])
        elif "raise" in modifier:
            new = min(level + modifier["raise"], ceiling)
        else:
            new = max(level - modifier["lower"], 0)
        verb = "Raised" if new > level else "Lowered" if new < level else "Kept"
        level = new
        rationale.append(f"{verb} to {levels[level]}: {reason}")
    for delta, reason in automatic:
        new = max(min(level + delta, ceiling), 0)
        verb = "Raised" if new > level else "Lowered" if new < level else "Kept"
        level = new
        rationale.append(f"{verb} to {levels[level]}: {reason}")
    return levels[level], rationale


def _render(template: str, context: dict[str, Any]) -> str:
    def value(match: re.Match[str]) -> str:
        found = None
        for name in match.group(1).split("|"):
            found = context.get(name)
            if found is not None and found != []:
                break
        if found is None or found == []:
            return "unknown"
        if isinstance(found, list):
            return ", ".join(str(v) for v in found)
        return str(found)

    return _PLACEHOLDER.sub(value, template)


def build_finding(candidate: Candidate, params: dict[str, Any]) -> dict[str, Any]:
    rule = candidate.rule
    evidence = [event for event, _ in candidate.events]
    stamps = candidate.timestamps()
    first, last = (min(stamps), max(stamps)) if stamps else (None, None)

    entities: dict[str, Any] = {_short(k): v for k, v in candidate.key.items() if k != "event_id"}
    for name in (*_SUMMARY_FIELDS, *rule.spec.get("entities", [])):
        short = _short(name)
        if short in entities:
            continue
        get = field_getter(name)
        values = sorted({str(v) for e in evidence for v in _as_list(get(e))} - {"None"})
        if len(values) == 1:
            entities[short] = values[0]
        elif 1 < len(values) <= _TOP_VALUES and name in rule.spec.get("entities", []):
            entities[short] = values
    if rule.type == "correlation":
        for other in candidate.related:
            for name, value in other.key.items():
                if name != "event_id":
                    entities.setdefault(_short(name), value)

    distinct = {}
    top_values = {}
    for name in _SUMMARY_FIELDS:
        get = field_getter(name)
        counts = Counter(str(v) for e in evidence if (v := get(e)) is not None)
        if counts:
            distinct[name] = len(counts)
            top_values[name] = counts.most_common(_TOP_VALUES)

    automatic: list[tuple[int, str]] = []
    if any(e["parsing_status"] != "parsed" for e in evidence):
        automatic.append((-1, "Some supporting records were only partially parsed"))
    files = {e["source_file_id"] for e in evidence}
    hinted = any(e["timezone_assumption"].startswith("analyst_hint:") for e in evidence)
    if rule.type in ("sequence", "correlation") and len(files) > 1 and hinted:
        automatic.append((-1, "Ordering across sources depends on analyst-supplied timezone hints"))
    severity, severity_rationale = _rate(candidate, evidence, "severity", SEVERITIES, [])
    confidence, confidence_rationale = _rate(
        candidate, evidence, "confidence", CONFIDENCES, automatic
    )

    context: dict[str, Any] = {
        **{k: v for k, v in entities.items()},
        "count": candidate.weighted_count,
        "event_count": candidate.event_count,
        "first": _iso(first),
        "last": _iso(last),
        **{f"distinct.{_short(k)}": v for k, v in distinct.items()},
        **{f"params.{k}": v for k, v in params.items()},
        **{k: v for k, v in candidate.facts.items() if isinstance(v, int | str)},
    }
    observed = {
        "event_count": candidate.event_count,
        "weighted_count": candidate.weighted_count,
        "evidence_events_linked": len(candidate.events),
        "evidence_truncated": candidate.event_count > len(candidate.events),
        "distinct": distinct,
        "top_values": top_values,
        "sample_event_ids": [e["event_id"] for e in evidence[:5]],
        "params": params,
        **candidate.facts,
    }
    return {
        "fingerprint": fingerprint(candidate),
        "rule_id": rule.id,
        "rule_version": rule.version,
        "title": _render(rule.spec["title"], context),
        "description": _render(rule.spec["description"], context),
        "severity": severity,
        "severity_rationale": severity_rationale,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "evidence_strength": rule.spec["evidence_strength"],
        "attack_techniques": rule.spec["attack"],
        "first_observed_utc": first,
        "last_observed_utc": last,
        "entities": entities,
        "observed_evidence": observed,
        "interpretation": _render(rule.spec["interpretation"], context),
        "alternative_explanations": [
            _render(text, context) for text in rule.spec["alternative_explanations"]
        ],
        "verification_steps": [_render(text, context) for text in rule.spec["verification_steps"]],
        "event_count": candidate.event_count,
        "evidence": [(e["event_id"], role) for e, role in candidate.events],
        "evidence_files": sorted(files),
        "related_fingerprints": [fingerprint(other) for other in candidate.related],
    }


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]
