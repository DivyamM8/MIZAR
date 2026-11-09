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
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, Connection, literal_column, select

from mizar.db.tables import event_group_members, event_groups, events
from mizar.detection.conditions import Event, compile_filter, field_getter, sql_prefilter
from mizar.detection.rules import CONFIDENCES, SEVERITIES, Rule, load_rules

EVIDENCE_CAP = 10_000
_CORRELATION_EVIDENCE_PER_FINDING = 50
_FIRST_SEEN_EVIDENCE = 20  # per new value
# Groups tracked per rule during detection; findings are capped lower afterwards (runs.py).
MAX_CANDIDATES_PER_RULE = 20_000
_FIRST_SEEN_LISTED = 100  # new values listed per finding (all are counted)
_SUMMARY_FIELDS = ("hostname", "username", "source_ip", "destination_ip", "destination_port")
_TOP_VALUES = 5
# Fields the engine itself reads, whatever the rules say (weights, ratings, evidence).
_ENGINE_FIELDS = frozenset(
    {
        "event_id",
        "timestamp_utc",
        "timezone_assumption",
        "parsing_status",
        "source_file_id",
        "source_type",
        "extra.repeat_count",
        *_SUMMARY_FIELDS,
    }
)
_FIELD_LIST_KEYS = ("group_by", "entities", "key", "join", "distinct")
_CASE_NOT_INDEXED: ColumnElement[str] = literal_column("+events.case_id")
_PLACEHOLDER = re.compile(
    r"\{([a-z][a-z_]*(?:\.[a-z][a-z_]*)?(?:\|[a-z][a-z_]*(?:\.[a-z][a-z_]*)?)*)\}"
)


def rule_fields(spec: Any) -> set[str]:
    """Every event field a rule refers to: filter and modifier conditions, grouping,
    entity, join and distinct fields, wherever they appear in the rule."""
    found: set[str] = set()
    if isinstance(spec, dict):
        for key, value in spec.items():
            if key in ("field", *_FIELD_LIST_KEYS) and isinstance(value, str):
                found.add(value)
            elif key in _FIELD_LIST_KEYS and isinstance(value, list):
                found.update(v for v in value if isinstance(v, str))
            found |= rule_fields(value)
    elif isinstance(spec, list):
        for item in spec:
            found |= rule_fields(item)
    return found


_MULTIPLE = object()  # a field with more than one value across a candidate's events


@dataclass(eq=False)
class Candidate:
    """One rule's match for one grouping key.

    Evidence is kept as (event ID, role); the events themselves are fetched when the
    finding is built, so memory grows with the number of candidates, not events.
    """

    rule: Rule
    key: dict[str, Any]
    evidence: list[tuple[str, str]] = field(default_factory=list)
    event_count: int = 0
    weighted_count: int = 0
    facts: dict[str, Any] = field(default_factory=dict)
    related: list[Candidate] = field(default_factory=list)
    # Only rule types that can offer the same event twice (sequence, correlation) need
    # to remember every event ID they counted.
    dedupe: bool = True
    first: datetime | None = None
    last: datetime | None = None
    # Summary field -> its value across all counted events, or _MULTIPLE.
    values: dict[str, Any] = field(default_factory=dict)
    _seen: set[str] = field(default_factory=set)

    def add(self, event: Event, role: str, weight: int = 1) -> None:
        if not self._count(event["event_id"], weight):
            return
        stamp = event["timestamp_utc"]
        if stamp is not None:
            self.first = stamp if self.first is None else min(self.first, stamp)
            self.last = stamp if self.last is None else max(self.last, stamp)
        for name in _SUMMARY_FIELDS:
            value = event.get(name)
            if value is None:
                continue
            current = self.values.get(name)
            if current is None:
                self.values[name] = value
            elif current is not _MULTIPLE and current != value:
                self.values[name] = _MULTIPLE
        if len(self.evidence) < EVIDENCE_CAP:
            self.evidence.append((event["event_id"], role))

    def add_reference(self, event_id: str, role: str) -> None:
        """Evidence from another candidate (correlation); its times come via `related`."""
        if self._count(event_id, 1) and len(self.evidence) < EVIDENCE_CAP:
            self.evidence.append((event_id, role))

    def _count(self, event_id: str, weight: int) -> bool:
        if self.dedupe:
            if event_id in self._seen:
                return False
            self._seen.add(event_id)
        self.event_count += 1
        self.weighted_count += weight
        return True

    def timestamps(self) -> list[datetime]:
        stamps = [s for s in (self.first, self.last) if s is not None]
        for other in self.related:
            stamps.extend(other.timestamps())
        return stamps

    def entity(self, name: str) -> Any:
        """The candidate's single value for a field: its key, else a unique evidence value."""
        if name in self.key:
            return self.key[name]
        if name not in _SUMMARY_FIELDS:
            raise ValueError(f"correlation joins must be one of {_SUMMARY_FIELDS}, not {name!r}")
        value = self.values.get(name)
        return None if value is _MULTIPLE else value


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
    def __init__(
        self,
        conn: Connection,
        case_id: str,
        params: dict[str, dict[str, Any]],
        rules: tuple[Rule, ...] | list[Rule] = (),
    ) -> None:
        self.conn = conn
        self.case_id = case_id
        self.params = params
        self.notes: dict[str, dict[str, Any]] = defaultdict(dict)
        self.duplicate_of = self._duplicate_groups()
        # Events held in memory carry only the fields some rule uses: correlation rules
        # read events held by other rules' candidates, so the set covers every rule.
        fields = set(_ENGINE_FIELDS)
        for rule in rules or load_rules():
            fields |= rule_fields(rule.spec)
        names = {f for f in fields if not f.startswith("extra.")}
        self._columns = [c for c in events.columns if c.name in names]
        self._extra_keys = frozenset(f.split(".")[1] for f in fields if f.startswith("extra."))

    def _duplicate_groups(self) -> dict[str, str]:
        rows = self.conn.execute(
            select(event_group_members.c.event_id, event_group_members.c.group_id)
            .join(event_groups, event_groups.c.group_id == event_group_members.c.group_id)
            .where(event_groups.c.case_id == self.case_id, event_groups.c.group_type == "duplicate")
        )
        return {event_id: group_id for event_id, group_id in rows}

    def _param(self, rule: Rule, name: str) -> Any:
        return rule.params[name].native(self.params[rule.id][name])

    def _event(self, row: Any) -> Event:
        event = dict(row)
        extra = event.get("extra")
        if isinstance(extra, dict):
            event["extra"] = {k: v for k, v in extra.items() if k in self._extra_keys}
        return event

    def fetch(self, event_ids: list[str]) -> dict[str, Event]:
        """Events by ID, with the same fields as streamed events."""
        found: dict[str, Event] = {}
        for start in range(0, len(event_ids), 500):
            chunk = event_ids[start : start + 500]
            query = select(*self._columns, events.c.extra).where(events.c.event_id.in_(chunk))
            for row in self.conn.execute(query).mappings():
                found[row["event_id"]] = self._event(row)
        return found

    def _stream(self, rule: Rule, spec: Any) -> Iterator[Event]:
        prefilter = sql_prefilter(spec)
        case_column = _CASE_NOT_INDEXED if prefilter else events.c.case_id
        query = select(*self._columns, events.c.extra).where(
            case_column == self.case_id, *prefilter
        )
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
            yield self._event(row)

    def _note_without_utc(self, rule: Rule, count: int) -> None:
        if count:
            self.notes[rule.id]["events_without_utc_skipped"] = count

    # --- rule types ------------------------------------------------------------------

    def run(self, rule: Rule, base: dict[str, list[Candidate]] | None = None) -> list[Candidate]:
        self._skipped_groups: set[Token] = set()
        if rule.type == "match":
            found = self._match(rule)
        elif rule.type == "threshold":
            found = self._threshold(rule)
        elif rule.type == "sequence":
            found = self._sequence(rule)
        elif rule.type == "first_seen":
            found = self._first_seen(rule)
        else:
            found = self._correlation(rule, base or {})
        if self._skipped_groups:
            self.notes[rule.id]["groups_not_evaluated"] = (
                f"More than {MAX_CANDIDATES_PER_RULE} groups matched; "
                f"{len(self._skipped_groups)} later group(s) were not evaluated."
            )
        return found

    def _candidate(
        self,
        rule: Rule,
        groups: dict[Token, Candidate],
        token: Token,
        key: dict[str, Any],
        dedupe: bool = True,
    ) -> Candidate | None:
        """The group's candidate, created if there is room (memory stays bounded)."""
        candidate = groups.get(token)
        if candidate is None:
            if len(groups) >= MAX_CANDIDATES_PER_RULE:
                self._skipped_groups.add(token)
                return None
            candidate = groups[token] = Candidate(rule, key, dedupe=dedupe)
        return candidate

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
            candidate = self._candidate(rule, groups, _token(key), key, dedupe=False)
            if candidate is not None:
                candidate.add(event, "trigger", _weight(event))
        return list(groups.values())

    def _threshold(self, rule: Rule) -> list[Candidate]:
        """Windows where a group's count (or distinct count) reaches the threshold.

        One pass in time order. Each group keeps only the events inside its window;
        overlapping windows that reach the threshold form one burst, and every event
        of a burst is evidence.
        """
        assert rule.predicate is not None
        block = rule.spec["threshold"]
        need = self._param(rule, block["count"])
        window: timedelta = self._param(rule, block["window"])
        distinct = field_getter(block["distinct"]) if "distinct" in block else None
        once = block.get("count_duplicates_once", True)
        group_by = rule.spec["group_by"]
        states: dict[Token, _Series] = {}
        groups: dict[Token, Candidate] = {}
        seen_duplicates: dict[Token, set[str]] = defaultdict(set)
        without_utc = 0
        for count, event in enumerate(self._stream(rule, rule.spec["filter"]), start=1):
            if not rule.predicate(event):
                continue
            stamp = event["timestamp_utc"]
            if stamp is None:
                without_utc += 1
                continue
            key = self._group_key(rule, event, group_by)
            token = _token(key)
            duplicate = self.duplicate_of.get(event["event_id"])
            if once and duplicate is not None:
                if duplicate in seen_duplicates[token]:
                    continue  # the same record collected twice counts once
                seen_duplicates[token].add(duplicate)
            series = states.get(token)
            if series is None:
                series = states[token] = _Series()
            reached = series.push(
                event,
                stamp,
                _weight(event),
                distinct(event) if distinct else None,
                window,
                need,
                distinct is not None,
            )
            if reached:
                candidate = self._candidate(rule, groups, token, key, dedupe=False)
                if candidate is not None:
                    series.burst_into(candidate)
            if count % 50_000 == 0:  # forget groups whose window has emptied without a burst
                stale = [t for t, s in states.items() if not s.bursts and s.idle(stamp, window)]
                for t in stale:
                    del states[t]
        self._note_without_utc(rule, without_utc)
        for token, candidate in groups.items():
            candidate.facts["bursts"] = states[token].finish(distinct is not None)
        return list(groups.values())

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
        for count, event in enumerate(self._stream(rule, combined), start=1):
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
                    candidate = self._candidate(rule, groups, _token(key), key)
                    if candidate is not None:
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
                # Older entries can never be in a later window either.
                while earlier and stamp - earlier[0][0] > window:
                    earlier.popleft()
                earlier.append((stamp, _weight(event), event))
            if count % 50_000 == 0:
                for t in [t for t, q in pending.items() if not q or stamp - q[-1][0] > window]:
                    del pending[t]
        self._note_without_utc(rule, without_utc)
        for candidate in groups.values():
            counts = [m[f"{first['name']}_count"] for m in candidate.facts["matches"]]
            candidate.facts[f"{first['name']}_count"] = max(counts)
        return list(groups.values())

    def _first_seen(self, rule: Rule) -> list[Candidate]:
        """Values of `key` first seen after the baseline. With group_by, one candidate per
        group lists all of its new values (e.g. per user: every new source address)."""
        assert rule.predicate is not None
        keys = rule.spec["first_seen"]["key"]
        group_by = rule.spec.get("group_by", keys)
        baseline: timedelta = self._param(rule, rule.spec["first_seen"]["baseline"])
        start: datetime | None = None
        last: datetime | None = None
        seen: set[Token] = set()
        novel: dict[Token, tuple[Candidate, list[int]]] = {}
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
            if token in novel:
                candidate, occurrences = novel[token]
                occurrences[0] += 1
                if occurrences[0] <= _FIRST_SEEN_EVIDENCE:
                    candidate.add(event, "later_occurrence")
                else:
                    candidate.event_count += 1
                continue
            if token in seen:
                continue
            seen.add(token)
            if stamp > start + baseline:
                group_key = self._group_key(rule, event, group_by)
                group = self._candidate(rule, found, _token(group_key), group_key, dedupe=False)
                if group is None:
                    continue
                if not group.facts:
                    group.facts.update(
                        baseline_end_utc=_iso(start + baseline), first_seen_count=0, first_seen=[]
                    )
                group.add(event, "first_occurrence")
                group.facts["first_seen_count"] += 1
                if len(group.facts["first_seen"]) < _FIRST_SEEN_LISTED:
                    group.facts["first_seen"].append({**key, "first_utc": _iso(stamp)})
                novel[token] = (group, [1])
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
                key = {join: value}
                candidate = self._candidate(rule, groups, _token(key), key)
                if candidate is None:
                    continue
                for step, item in ((block["first"], f_item), (block["then"], t_item)):
                    if isinstance(item, Candidate):
                        if all(item is not known for known in candidate.related):
                            candidate.related.append(item)
                            for event_id, _ in item.evidence[:_CORRELATION_EVIDENCE_PER_FINDING]:
                                candidate.add_reference(event_id, f"{step['name']}:{item.rule.id}")
                    else:
                        candidate.add(item, step["name"])
        for candidate in groups.values():
            candidate.facts["chain"] = [
                {"rule_id": other.rule.id, "key": other.key} for other in candidate.related
            ]
        return list(groups.values())


class _Series:
    """One threshold group's events inside the current window, and its bursts so far."""

    __slots__ = ("added", "burst_end", "bursts", "items", "next_seq", "total", "values")

    def __init__(self) -> None:
        # (sequence number, time, weight, distinct value, event)
        self.items: deque[tuple[int, datetime, int, Any, Event]] = deque()
        self.total = 0
        self.values: Counter[Any] = Counter()
        self.next_seq = 0
        self.burst_end = -1  # sequence number of the last event in the current burst
        self.added = -1  # last sequence number already given to the candidate
        self.bursts: list[dict[str, Any]] = []

    def push(
        self,
        event: Event,
        stamp: datetime,
        weight: int,
        value: Any,
        window: timedelta,
        need: int,
        distinct: bool,
    ) -> bool:
        """Add an event; True if the window now reaches the threshold."""
        self.items.append((self.next_seq, stamp, weight, value, event))
        self.next_seq += 1
        self.total += weight
        if distinct and value is not None:
            self.values[value] += 1
        while stamp - self.items[0][1] > window:
            _, _, old_weight, old_value, _ = self.items.popleft()
            self.total -= old_weight
            if distinct and old_value is not None:
                self.values[old_value] -= 1
                if not self.values[old_value]:
                    del self.values[old_value]
        return (len(self.values) if distinct else self.total) >= need

    def burst_into(self, candidate: Candidate) -> None:
        """The window reached the threshold: extend the current burst, or start one."""
        if self.items[0][0] > self.burst_end:  # no overlap with the last burst
            self.bursts.append({"start_utc": None, "end_utc": None, "count": 0, "_values": set()})
        burst = self.bursts[-1]
        for seq, stamp, weight, value, event in self.items:
            if seq <= self.added:
                continue
            candidate.add(event, "trigger", weight)
            burst["start_utc"] = burst["start_utc"] or _iso(stamp)
            burst["end_utc"] = _iso(stamp)
            burst["count"] += weight
            if value is not None:
                burst["_values"].add(value)
            self.added = seq
        self.burst_end = self.items[-1][0]

    def idle(self, now: datetime, window: timedelta) -> bool:
        return not self.items or now - self.items[-1][1] > window

    def finish(self, distinct: bool) -> list[dict[str, Any]]:
        for burst in self.bursts:
            values = burst.pop("_values")
            if distinct:
                burst["distinct"] = len(values)
        return self.bursts


def human_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    parts: list[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size or (unit == "s" and not parts):
            parts.append(f"{seconds // size}{unit}")
            seconds %= size
    return " ".join(parts)


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


def build_finding(
    candidate: Candidate,
    params: dict[str, Any],
    fetch: Callable[[list[str]], dict[str, Event]],
) -> dict[str, Any]:
    rule = candidate.rule
    loaded = fetch([event_id for event_id, _ in candidate.evidence])
    evidence = [loaded[event_id] for event_id, _ in candidate.evidence if event_id in loaded]
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
        "evidence_events_linked": len(candidate.evidence),
        "evidence_truncated": candidate.event_count > len(candidate.evidence),
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
        "evidence": list(candidate.evidence),
        "evidence_files": sorted(files),
        "related_fingerprints": [fingerprint(other) for other in candidate.related],
    }


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]
