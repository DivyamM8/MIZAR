"""Rule filter language (DESIGN.md §9.1).

A filter is {all: [...]}, {any: [...]}, {not: filter} or a condition
{field, op, value, ignore_case}. Fields are event columns or extra.<path>.
When a field holds a list, a condition matches if any element matches.
String comparisons ignore case unless ignore_case: false. Regexes use RE2,
which runs in linear time, so a hostile log line cannot stall a rule.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from functools import lru_cache
from typing import Any

import re2

from mizar.db.tables import events

Event = dict[str, Any]
Predicate = Callable[[Event], bool]

OPERATORS = frozenset(
    {
        "eq",
        "neq",
        "in",
        "contains",
        "startswith",
        "endswith",
        "regex",
        "cidr",
        "exists",
        "gte",
        "lte",
    }
)
EVENT_COLUMNS = frozenset(column.name for column in events.columns)
# Columns whose stored values are canonical (lowercase identifiers or digits), so an
# exact SQL comparison selects the same events as the case-insensitive rule check.
_SQL_PREFILTER_COLUMNS = frozenset(
    {"event_type", "event_category", "event_outcome", "source_type", "event_code", "parsing_status"}
)


class FilterError(ValueError):
    pass


def field_getter(path: str) -> Callable[[Event], Any]:
    if path.startswith("extra."):
        keys = path.split(".")[1:]

        def get_extra(event: Event) -> Any:
            value: Any = event.get("extra")
            for key in keys:
                if not isinstance(value, dict):
                    return None
                value = value.get(key)
            return value

        return get_extra
    if path not in EVENT_COLUMNS:
        raise FilterError(f"unknown field {path!r}")
    return lambda event: event.get(path)


@lru_cache(maxsize=65536)
def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _leaf(spec: dict[str, Any]) -> Predicate:
    field = spec.get("field")
    op = spec.get("op")
    if not isinstance(field, str) or op not in OPERATORS:
        raise FilterError(f"invalid condition {spec!r}")
    get = field_getter(field)
    ignore_case = spec.get("ignore_case", True)
    value = spec.get("value")

    def norm(item: Any) -> Any:
        return item.lower() if ignore_case and isinstance(item, str) else item

    if op == "exists":
        wanted = value is not False

        def exists(event: Event) -> bool:
            found = get(event)
            present = found is not None and found != "" and found != []
            return present is wanted

        return exists

    test: Callable[[Any], bool]
    if op in ("eq", "neq"):
        target = norm(value)
        test = lambda item: norm(item) == target  # noqa: E731
    elif op == "in":
        if not isinstance(value, list):
            raise FilterError(f"'in' needs a list: {spec!r}")
        choices = {norm(v) for v in value}
        test = lambda item: norm(item) in choices  # noqa: E731
    elif op in ("contains", "startswith", "endswith"):
        needles = [norm(v) for v in (value if isinstance(value, list) else [value])]
        if not all(isinstance(n, str) for n in needles):
            raise FilterError(f"{op} needs strings: {spec!r}")
        checks: dict[str, Callable[[str, str], bool]] = {
            "contains": lambda text, needle: needle in text,
            "startswith": lambda text, needle: text.startswith(needle),
            "endswith": lambda text, needle: text.endswith(needle),
        }
        check = checks[op]

        def test(item: Any) -> bool:
            if item is None:
                return False
            text = norm(str(item))
            return any(check(text, needle) for needle in needles)

    elif op == "regex":
        if not isinstance(value, str):
            raise FilterError(f"regex needs a pattern string: {spec!r}")
        options = re2.Options()
        options.case_sensitive = not ignore_case
        options.log_errors = False
        try:
            pattern = re2.compile(value, options)
        except re2.error as exc:
            raise FilterError(f"invalid or unsupported regex {value!r}: {exc}") from exc
        test = lambda item: item is not None and pattern.search(str(item)) is not None  # noqa: E731
    elif op == "cidr":
        if not isinstance(value, list):
            raise FilterError(f"cidr needs a list of networks: {spec!r}")
        try:
            networks = [ipaddress.ip_network(v, strict=False) for v in value]
        except (TypeError, ValueError) as exc:
            raise FilterError(f"invalid cidr list {value!r}") from exc

        def test(item: Any) -> bool:
            address = _ip(str(item)) if item is not None else None
            return address is not None and any(
                address.version == net.version and address in net for net in networks
            )

    else:  # gte / lte
        bound = _number(value)
        if bound is None:
            raise FilterError(f"{op} needs a number: {spec!r}")

        def test(item: Any) -> bool:
            number = _number(item)
            return number is not None and (number >= bound if op == "gte" else number <= bound)

    def predicate(event: Event) -> bool:
        found = get(event)
        if isinstance(found, list):
            return any(test(item) for item in found)
        return test(found)

    if op == "neq":
        # neq on a list: no element equals the value.
        def negated(event: Event) -> bool:
            found = get(event)
            if isinstance(found, list):
                return not any(test(item) for item in found)
            return not test(found)

        return negated
    return predicate


def compile_filter(spec: Any) -> Predicate:
    if not isinstance(spec, dict):
        raise FilterError(f"filter must be a mapping: {spec!r}")
    if "all" in spec:
        parts = [compile_filter(item) for item in spec["all"]]
        return lambda event: all(part(event) for part in parts)
    if "any" in spec:
        parts = [compile_filter(item) for item in spec["any"]]
        return lambda event: any(part(event) for part in parts)
    if "not" in spec:
        inner = compile_filter(spec["not"])
        return lambda event: not inner(event)
    return _leaf(spec)


def iter_conditions(spec: Any) -> Iterator[dict[str, Any]]:
    """Every leaf condition of a filter."""
    if not isinstance(spec, dict):
        return
    for key in ("all", "any"):
        for item in spec.get(key, []):
            yield from iter_conditions(item)
    if "not" in spec:
        yield from iter_conditions(spec["not"])
    if "field" in spec:
        yield spec


def referenced_fields(spec: Any) -> set[str]:
    return {condition["field"] for condition in iter_conditions(spec)}


def _allowed_values(spec: Any) -> dict[str, set[str]]:
    """Canonical columns a filter restricts to fixed values: {column: allowed values}.

    For 'all', every restricted column applies; for 'any', a column applies only if
    every branch restricts it (the allowed values are then the union).
    """
    if not isinstance(spec, dict):
        return {}
    if "any" in spec:
        branches = [_allowed_values(branch) for branch in spec["any"]]
        if not branches:
            return {}
        common = set.intersection(*(set(b) for b in branches))
        return {column: set().union(*(b[column] for b in branches)) for column in common}
    leaves = spec.get("all", [spec] if "field" in spec else [])
    allowed: dict[str, set[str]] = {}
    for leaf in leaves:
        if not isinstance(leaf, dict):
            continue
        if "any" in leaf or "all" in leaf:
            for column, values in _allowed_values(leaf).items():
                allowed[column] = allowed[column] & values if column in allowed else values
            continue
        field = leaf.get("field")
        if field not in _SQL_PREFILTER_COLUMNS:
            continue
        op, value = leaf.get("op"), leaf.get("value")
        listed = [value] if op == "eq" else value if op == "in" else None
        if not isinstance(listed, list) or not all(
            isinstance(v, str) and v == v.lower() for v in listed
        ):
            continue
        allowed[field] = allowed[field] & set(listed) if field in allowed else set(listed)
    return allowed


def sql_prefilter(spec: Any) -> list[Any]:
    """SQL conditions implied by the filter on canonical (indexed) columns.

    They only narrow what is loaded; every event is still checked by the full
    predicate in Python, so the SQL never decides a match on its own.
    """
    return [
        events.c[column].in_(sorted(values))
        for column, values in sorted(_allowed_values(spec).items())
    ]
