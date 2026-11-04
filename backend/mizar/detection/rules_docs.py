"""Render docs/rules.md from the rule files: python -m mizar.detection.rules_docs"""

from __future__ import annotations

import sys

from mizar.detection.rules import load_rules
from mizar.versions import RULE_FORMAT_VERSION


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def render() -> str:
    rules = load_rules()
    lines = [
        "# Detection rules",
        "",
        f"{len(rules)} rules, rule format {RULE_FORMAT_VERSION}. Generated from "
        "`backend/mizar/rules/*.yaml` by `python -m mizar.detection.rules_docs`; do not edit "
        "by hand. Severity and confidence below are base values; each finding records the "
        "modifiers that changed them.",
        "",
        "| ID | Version | Type | ATT&CK | Severity | Confidence | Evidence | Title |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for rule in rules:
        spec = rule.spec
        lines.append(
            f"| {rule.id} | {rule.version} | {rule.type} | {', '.join(spec['attack'])} | "
            f"{spec['severity']['base']} | {spec['confidence']['base']} | "
            f"{spec['evidence_strength']} | {_cell(spec['title'])} |"
        )
    for rule in rules:
        spec = rule.spec
        lines += ["", f"## {rule.id} — {_cell(spec['title'])}", "", _cell(spec["description"]), ""]
        if rule.params:
            lines.append("Parameters:")
            lines.append("")
            for param in rule.params.values():
                lines.append(
                    f"- `{param.name}` ({param.kind}, default `{param.default}`): "
                    f"{_cell(param.description)}"
                )
            lines.append("")
        lines.append("Alternative explanations:")
        lines.append("")
        lines += [f"- {_cell(text)}" for text in spec["alternative_explanations"]]
        lines += ["", "Verification steps:", ""]
        lines += [f"- {_cell(text)}" for text in spec["verification_steps"]]
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.stdout.write(render())
