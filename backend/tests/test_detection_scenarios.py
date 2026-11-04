"""Ground truth: every planted behavior is found, and nothing else is."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from .analysis_helpers import RunJobs, analyze, new_case, upload

ATTACK_SCENARIOS = ["linux_intrusion", "web_intrusion", "windows_spray", "network_scan"]


def _matches(finding: dict[str, Any], wanted: dict[str, Any]) -> bool:
    entities = finding["entities"]
    for key, value in wanted.items():
        found = entities.get(key)
        if isinstance(found, list) and value in found:
            continue
        if found != value:
            return False
    return True


@pytest.mark.parametrize("name", ATTACK_SCENARIOS)
def test_planted_activity_is_found_exactly(
    name: str,
    scenarios: Path,
    api: TestClient,
    run_jobs: RunJobs,
) -> None:
    directory = scenarios / name
    truth = json.loads((directory / "ground_truth.json").read_text())
    case_id = new_case(api, name)
    for spec in truth["files"]:
        upload(
            api,
            case_id,
            (directory / spec["path"]).read_bytes(),
            spec["path"],
            **spec.get("hints", {}),
        )
    run, findings = analyze(api, run_jobs, case_id)
    assert run["status"] == "succeeded", run
    assert run["results"]["rule_errors"] == []

    planted = sorted({p["rule_id"] for p in truth["planted"]})
    assert sorted({f["rule_id"] for f in findings}) == planted
    for plant in truth["planted"]:
        candidates = [f for f in findings if f["rule_id"] == plant["rule_id"]]
        assert any(_matches(f, plant["entities"]) for f in candidates), (plant, candidates)
    for lookalike in truth["benign_lookalikes"]:
        rule = lookalike.get("must_not_match")
        if not rule:
            continue
        wanted = {k: v for k, v in rule.items() if k != "rule_id"}
        hits = [f for f in findings if f["rule_id"] == rule["rule_id"] and _matches(f, wanted)]
        assert hits == [], lookalike["description"]
    for finding in findings:
        text = " ".join([finding["title"], finding["description"], finding["interpretation"]])
        assert "unknown" not in text, (finding["rule_id"], text)
        assert finding["severity_rationale"][0].startswith("Base severity")
        assert finding["source_files"] and all(f["sha256"] for f in finding["source_files"])


def test_critical_requires_brute_force_and_privileged_group(
    scenarios: Path,
    api: TestClient,
    run_jobs: RunJobs,
) -> None:
    directory = scenarios / "linux_intrusion"
    case_id = new_case(api)
    upload(
        api,
        case_id,
        (directory / "auth.log").read_bytes(),
        "auth.log",
        timezone_hint="UTC",
        year_hint=2026,
    )
    _, findings = analyze(api, run_jobs, case_id)
    chain = next(f for f in findings if f["rule_id"] == "CORR-002")
    assert chain["severity"] == "critical"
    assert "privileged group" in chain["severity_rationale"][-1]
    related = {
        api.get(f"/api/findings/{fid}").json()["rule_id"] for fid in chain["related_finding_ids"]
    }
    assert {"AUTH-003", "PRIV-003", "PERS-001"} <= related
    assert findings[0]["rule_id"] == "CORR-002"  # priority order puts critical first
