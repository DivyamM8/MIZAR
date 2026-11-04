"""Rule loading and validation (DESIGN.md §9.1).

Rules are YAML files in mizar/rules, one rule per file. Loading validates the
JSON Schema, then semantics: referenced parameters and fields exist, regexes
compile under RE2, correlation steps reference existing base rules, Critical
severity is reachable only in correlation rules (§11.3), and no text uses
wording that states a compromise as fact (§11.4). Any problem raises
RuleError; MIZAR refuses to run with an invalid rule set.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cache
from importlib.resources import files
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from mizar.core.errors import ErrorCode, MizarError
from mizar.detection.conditions import (
    FilterError,
    Predicate,
    compile_filter,
    field_getter,
    referenced_fields,
)
from mizar.versions import RULE_FORMAT_VERSION

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
EVIDENCE_STRENGTHS = ("direct", "corroborated", "circumstantial", "inferred")
MODIFIER_CONDITIONS = frozenset(
    {"count_gte", "distinct_gte", "any_event", "all_events", "all_events_parsed", "includes_rules"}
)
_DURATION = re.compile(r"^(\d+)([smhd])$")
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
# {name}, {group.name}, or {a|b}: the first of several fields that has a value.
_PLACEHOLDER_NAME = re.compile(r"^[a-z][a-z_]*(\.[a-z][a-z_]*)?(\|[a-z][a-z_]*(\.[a-z][a-z_]*)?)*$")
# DESIGN.md §11.4: findings state hypotheses, never conclusions.
BANNED_WORDING = re.compile(
    r"\b(compromis\w*|breach\w*|hacked|malicious|attacker\w*|intruder\w*|confirmed|"
    r"succeeded in)\b",
    re.IGNORECASE,
)


class RuleError(MizarError):
    def __init__(self, rule: str, message: str) -> None:
        super().__init__(ErrorCode.RULE_INVALID, f"Rule {rule}: {message}", details={"rule": rule})


def parse_duration(text: str) -> timedelta:
    match = _DURATION.match(text)
    if not match:
        raise ValueError(f"invalid duration {text!r} (use e.g. 30s, 10m, 24h, 7d)")
    return timedelta(**{_DURATION_UNITS[match.group(2)]: int(match.group(1))})


@dataclass(frozen=True)
class Param:
    name: str
    kind: str
    default: Any
    minimum: int | None
    description: str

    def validate(self, value: Any) -> Any:
        """Return the stored (JSON) form of a value, or raise ValueError."""
        if self.kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{self.name} must be an integer")
            if self.minimum is not None and value < self.minimum:
                raise ValueError(f"{self.name} must be at least {self.minimum}")
            return value
        if not isinstance(value, str):
            raise ValueError(f"{self.name} must be a duration such as 10m")
        parse_duration(value)
        return value

    def native(self, value: Any) -> Any:
        return parse_duration(value) if self.kind == "duration" else value


@dataclass
class Rule:
    spec: dict[str, Any]
    file_name: str
    file_sha256: str
    params: dict[str, Param]
    predicate: Predicate | None
    step_predicates: dict[str, Predicate] = field(default_factory=dict)
    fields_used: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return str(self.spec["id"])

    @property
    def version(self) -> str:
        return str(self.spec["version"])

    @property
    def type(self) -> str:
        return str(self.spec["type"])

    @property
    def uses_extra(self) -> bool:
        return any(name.startswith("extra.") for name in self.fields_used)

    def effective_params(self, overrides: dict[str, Any]) -> dict[str, Any]:
        unknown = set(overrides) - set(self.params)
        if unknown:
            raise MizarError(
                ErrorCode.RULE_PARAM_INVALID,
                f"Rule {self.id} has no parameter(s) {sorted(unknown)}.",
                details={"rule": self.id, "parameters": sorted(self.params)},
            )
        values = {}
        for name, param in self.params.items():
            value = overrides.get(name, param.default)
            try:
                values[name] = param.validate(value)
            except ValueError as exc:
                raise MizarError(
                    ErrorCode.RULE_PARAM_INVALID,
                    f"Rule {self.id}: {exc}.",
                    details={"rule": self.id, "parameter": name},
                ) from exc
        return values

    def catalogue_entry(self) -> dict[str, Any]:
        spec = self.spec
        return {
            "rule_id": self.id,
            "version": self.version,
            "status": spec["status"],
            "type": self.type,
            "title": spec["title"],
            "description": spec["description"],
            "attack": spec["attack"],
            "base_severity": spec["severity"]["base"],
            "base_confidence": spec["confidence"]["base"],
            "evidence_strength": spec["evidence_strength"],
            "params": {
                p.name: {"type": p.kind, "default": p.default, "description": p.description}
                for p in self.params.values()
            },
        }


@cache
def _schema_validator() -> Draft202012Validator:
    text = files("mizar.schemas").joinpath("rule.v1.json").read_text(encoding="utf-8")
    schema = json.loads(text)
    if schema["x-rule-format-version"] != RULE_FORMAT_VERSION:
        raise RuntimeError("rule schema file and RULE_FORMAT_VERSION disagree")
    return Draft202012Validator(schema)


def _check_text(rule_id: str, spec: dict[str, Any]) -> None:
    texts = [spec["title"], spec["description"], spec["interpretation"]]
    texts += spec["alternative_explanations"] + spec["verification_steps"]
    texts += [spec["severity"]["reason"], spec["confidence"]["reason"]]
    for rating in ("severity", "confidence"):
        texts += [m["reason"] for m in spec[rating].get("modifiers", [])]
    for text in texts:
        found = BANNED_WORDING.search(text)
        if found:
            raise RuleError(rule_id, f"wording {found.group(0)!r} states a conclusion (§11.4)")
    for text in (spec["title"], spec["description"], spec["interpretation"]):
        for name in _PLACEHOLDER.findall(text):
            if not _PLACEHOLDER_NAME.match(name):
                raise RuleError(rule_id, f"invalid template placeholder {{{name}}}")


def _require_param(rule_id: str, params: dict[str, Param], name: Any, kind: str) -> None:
    if name not in params:
        raise RuleError(rule_id, f"references undeclared parameter {name!r}")
    if params[name].kind != kind:
        raise RuleError(rule_id, f"parameter {name!r} must be of type {kind}")


def _check_rating(rule_id: str, spec: dict[str, Any], kind: str, levels: tuple[str, ...]) -> None:
    rating = spec[kind]
    if rating["base"] not in levels:
        raise RuleError(rule_id, f"invalid {kind} {rating['base']!r}")
    if kind == "severity" and rating["base"] == "critical":
        raise RuleError(rule_id, "no rule may have base severity critical (§11.3)")
    for modifier in rating.get("modifiers", []):
        actions = [key for key in ("set", "raise", "lower") if key in modifier]
        if len(actions) != 1:
            raise RuleError(rule_id, f"{kind} modifier needs exactly one of set/raise/lower")
        if "set" in modifier and modifier["set"] not in levels:
            raise RuleError(rule_id, f"invalid {kind} {modifier['set']!r}")
        if (
            kind == "severity"
            and modifier.get("set") == "critical"
            and spec["type"] != "correlation"
        ):
            raise RuleError(rule_id, "only correlation rules may reach critical (§11.3)")
        unknown = set(modifier["when"]) - MODIFIER_CONDITIONS
        if unknown or not modifier["when"]:
            raise RuleError(rule_id, f"unknown modifier condition(s) {sorted(unknown)}")
        for key in ("any_event", "all_events"):
            if key in modifier["when"]:
                compile_filter(modifier["when"][key])


def build_rule(spec: dict[str, Any], file_name: str, raw: bytes) -> Rule:
    rule_id = str(spec.get("id", file_name))
    errors = sorted(_schema_validator().iter_errors(spec), key=lambda e: list(e.path))
    if errors:
        location = "/".join(str(p) for p in errors[0].path) or "(root)"
        raise RuleError(rule_id, f"{location}: {errors[0].message}")
    if file_name != f"{rule_id}.yaml":
        raise RuleError(rule_id, f"file must be named {rule_id}.yaml")
    params: dict[str, Param] = {}
    for name, declared in spec.get("params", {}).items():
        param = Param(
            name,
            declared["type"],
            declared["default"],
            declared.get("minimum"),
            declared["description"],
        )
        try:
            param.validate(param.default)
        except ValueError as exc:
            raise RuleError(rule_id, f"default of {name}: {exc}") from exc
        params[name] = param

    kind = spec["type"]
    required = {
        "match": ("filter",),
        "threshold": ("filter", "threshold", "group_by"),
        "sequence": ("sequence",),
        "first_seen": ("filter", "first_seen"),
        "correlation": ("correlation",),
    }[kind]
    for key in required:
        if key not in spec:
            raise RuleError(rule_id, f"{kind} rules need '{key}'")

    used: set[str] = set(spec.get("group_by", [])) | set(spec.get("entities", []))
    try:
        predicate = compile_filter(spec["filter"]) if "filter" in spec else None
        used |= referenced_fields(spec.get("filter"))
        steps: dict[str, Predicate] = {}
        if kind == "threshold":
            block = spec["threshold"]
            _require_param(rule_id, params, block["count"], "integer")
            _require_param(rule_id, params, block["window"], "duration")
            if "distinct" in block:
                used.add(block["distinct"])
        elif kind == "sequence":
            block = spec["sequence"]
            _require_param(rule_id, params, block["window"], "duration")
            _require_param(rule_id, params, block["first"]["min_count"], "integer")
            used |= set(block["join"])
            for step in (block["first"], block["then"]):
                steps[step["name"]] = compile_filter(step["filter"])
                used |= referenced_fields(step["filter"])
        elif kind == "first_seen":
            _require_param(rule_id, params, spec["first_seen"]["baseline"], "duration")
            used |= set(spec["first_seen"]["key"])
        elif kind == "correlation":
            block = spec["correlation"]
            _require_param(rule_id, params, block["window"], "duration")
            for step in (block["first"], block["then"]):
                if ("findings" in step) == ("events" in step):
                    raise RuleError(rule_id, "a correlation step needs findings or events")
                if "events" in step:
                    steps[step["name"]] = compile_filter(step["events"])
                    used |= referenced_fields(step["events"])
        for name in used:
            field_getter(name)
    except FilterError as exc:
        raise RuleError(rule_id, str(exc)) from exc

    _check_rating(rule_id, spec, "severity", SEVERITIES)
    _check_rating(rule_id, spec, "confidence", CONFIDENCES)
    _check_text(rule_id, spec)
    return Rule(
        spec=spec,
        file_name=file_name,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        params=params,
        predicate=predicate,
        step_predicates=steps,
        fields_used=used,
    )


def validate_rule_set(rules: list[Rule]) -> None:
    ids = [rule.id for rule in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise RuleError(sorted(duplicates)[0], "duplicate rule id")
    by_id = {rule.id: rule for rule in rules}
    for rule in rules:
        if rule.type != "correlation":
            continue
        block = rule.spec["correlation"]
        for step in (block["first"], block["then"]):
            for referenced in step.get("findings", []):
                target = by_id.get(referenced)
                if target is None:
                    raise RuleError(rule.id, f"references unknown rule {referenced}")
                if target.type == "correlation":
                    raise RuleError(rule.id, "correlation rules cannot chain other correlations")


@cache
def load_rules() -> tuple[Rule, ...]:
    """The packaged rule set, validated, in rule-ID order."""
    rules = []
    for entry in sorted(files("mizar.rules").iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".yaml"):
            continue
        raw = entry.read_bytes()
        try:
            spec = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise RuleError(entry.name, f"invalid YAML: {exc}") from exc
        if not isinstance(spec, dict):
            raise RuleError(entry.name, "a rule file must contain one mapping")
        rules.append(build_rule(spec, entry.name, raw))
    validate_rule_set(rules)
    return tuple(sorted(rules, key=lambda r: r.id))
