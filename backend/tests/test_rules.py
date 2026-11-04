import copy
from typing import Any

import pytest
import yaml

from mizar.core.errors import MizarError
from mizar.detection.conditions import FilterError, compile_filter, sql_prefilter
from mizar.detection.rules import (
    RuleError,
    build_rule,
    load_rules,
    parse_duration,
    validate_rule_set,
)

EVENT = {
    "event_type": "logon_failed",
    "username": "Administrator",
    "source_ip": "203.0.113.5",
    "destination_port": 22,
    "extra": {"paths": ["/etc/hosts", "/etc/shadow"], "logon_type": 10, "url": "/a?id=1"},
}


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ({"field": "event_type", "op": "eq", "value": "LOGON_FAILED"}, True),
        ({"field": "event_type", "op": "eq", "value": "LOGON_FAILED", "ignore_case": False}, False),
        ({"field": "username", "op": "in", "value": ["administrator", "root"]}, True),
        ({"field": "username", "op": "neq", "value": "root"}, True),
        ({"field": "username", "op": "startswith", "value": ["adm", "x"]}, True),
        ({"field": "username", "op": "endswith", "value": "$"}, False),
        ({"field": "source_ip", "op": "cidr", "value": ["203.0.113.0/24"]}, True),
        ({"field": "source_ip", "op": "cidr", "value": ["10.0.0.0/8", "fc00::/7"]}, False),
        ({"field": "destination_port", "op": "gte", "value": 22}, True),
        ({"field": "destination_port", "op": "lte", "value": 21}, False),
        ({"field": "extra.logon_type", "op": "eq", "value": 10}, True),
        ({"field": "extra.paths", "op": "in", "value": ["/etc/shadow"]}, True),
        ({"field": "extra.paths", "op": "neq", "value": "/etc/shadow"}, False),
        ({"field": "extra.url", "op": "regex", "value": r"id=\d"}, True),
        ({"field": "extra.missing", "op": "exists"}, False),
        ({"field": "extra.missing", "op": "exists", "value": False}, True),
        ({"field": "process_name", "op": "contains", "value": "ssh"}, False),
        (
            {
                "any": [
                    {"field": "username", "op": "eq", "value": "x"},
                    {"field": "source_ip", "op": "exists"},
                ]
            },
            True,
        ),
        ({"not": {"field": "source_ip", "op": "exists"}}, False),
    ],
)
def test_operators(spec: dict[str, Any], expected: bool) -> None:
    assert compile_filter(spec)(EVENT) is expected


@pytest.mark.parametrize(
    "spec",
    [
        {"field": "nope", "op": "eq", "value": 1},
        {"field": "username", "op": "like", "value": "x"},
        {"field": "username", "op": "regex", "value": r"(a)\1"},  # backreference: not in RE2
        {"field": "source_ip", "op": "cidr", "value": ["not-a-net"]},
        {"field": "source_ip", "op": "cidr", "value": None},
        {"field": "username", "op": "in", "value": "root"},
        {"field": "destination_port", "op": "gte", "value": "many"},
    ],
)
def test_invalid_conditions_are_refused(spec: dict[str, Any]) -> None:
    with pytest.raises(FilterError):
        compile_filter(spec)


def test_sql_prefilter_only_for_canonical_columns() -> None:
    spec = {
        "all": [
            {"field": "event_type", "op": "in", "value": ["logon", "logon_failed"]},
            {"field": "username", "op": "eq", "value": "root"},
            {"field": "event_code", "op": "eq", "value": "4625"},
            {"field": "event_type", "op": "eq", "value": "MixedCase"},
        ]
    }
    rendered = [str(c) for c in sql_prefilter(spec)]
    assert len(rendered) == 2
    assert all("username" not in c for c in rendered)


def test_packaged_rule_set_is_valid() -> None:
    rules = load_rules()
    assert len(rules) == 32
    assert [r.id for r in rules] == sorted(r.id for r in rules)
    for rule in rules:
        assert rule.file_name == f"{rule.id}.yaml"
        assert rule.spec["severity"]["base"] != "critical"
        assert rule.spec["verification_steps"] and rule.spec["alternative_explanations"]
        rule.effective_params({})


def _base_rule() -> dict[str, Any]:
    rule = next(r for r in load_rules() if r.id == "AUTH-001")
    return copy.deepcopy(rule.spec)


def _build(spec: dict[str, Any]) -> Any:
    return build_rule(spec, f"{spec['id']}.yaml", yaml.safe_dump(spec).encode())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda s: s.update(interpretation="The attacker compromised the host."),
            "states a conclusion",
        ),
        (lambda s: s["threshold"].update(count="nope"), "undeclared parameter"),
        (lambda s: s["severity"].update(base="critical"), "critical"),
        (
            lambda s: s["severity"].update(
                modifiers=[{"when": {"count_gte": 1}, "set": "critical", "reason": "x"}]
            ),
            "only correlation",
        ),
        (lambda s: s.update(group_by=["no_such_field"]), "unknown field"),
        (lambda s: s.update(version="1.0"), "version"),
        (lambda s: s.update(attack=["T99"]), "attack"),
        (
            lambda s: s["confidence"].update(
                modifiers=[{"when": {"magic": True}, "raise": 1, "reason": "x"}]
            ),
            "unknown modifier",
        ),
        (lambda s: s.update(title="Brute force from {source_ip.__class__}"), "placeholder"),
        (lambda s: s.pop("threshold"), "need 'threshold'"),
    ],
)
def test_invalid_rules_are_refused(change: Any, message: str) -> None:
    spec = _base_rule()
    change(spec)
    with pytest.raises(RuleError) as info:
        _build(spec)
    assert message in info.value.message


def test_rule_file_name_must_match_id() -> None:
    spec = _base_rule()
    with pytest.raises(RuleError, match="must be named"):
        build_rule(spec, "other.yaml", b"")


def test_correlation_must_reference_base_rules() -> None:
    rules = list(load_rules())
    chain = next(r for r in rules if r.id == "CORR-001")
    broken = copy.deepcopy(chain.spec)
    broken["correlation"]["first"]["findings"] = ["WEB-999"]
    with pytest.raises(RuleError, match="unknown rule"):
        validate_rule_set([*[r for r in rules if r.id != "CORR-001"], _build(broken)])
    nested = copy.deepcopy(chain.spec)
    nested["correlation"]["first"]["findings"] = ["CORR-002"]
    with pytest.raises(RuleError, match="cannot chain"):
        validate_rule_set([*[r for r in rules if r.id != "CORR-001"], _build(nested)])


def test_parameter_overrides_are_validated() -> None:
    rule = next(r for r in load_rules() if r.id == "AUTH-001")
    assert rule.effective_params({"min_failures": 5})["min_failures"] == 5
    for bad in ({"min_failures": 1}, {"min_failures": "5"}, {"window": "ten"}, {"nope": 1}):
        with pytest.raises(MizarError):
            rule.effective_params(bad)


def test_durations() -> None:
    assert parse_duration("90s").total_seconds() == 90
    assert parse_duration("2h").total_seconds() == 7200
    with pytest.raises(ValueError):
        parse_duration("1.5h")


def test_rule_catalogue_doc_is_current() -> None:
    from pathlib import Path

    from mizar.detection.rules_docs import render

    doc = Path(__file__).resolve().parents[2] / "docs" / "rules.md"
    assert doc.read_text() == render(), "run: python -m mizar.detection.rules_docs > docs/rules.md"
