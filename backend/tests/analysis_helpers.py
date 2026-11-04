"""Helpers to take evidence through upload, parsing and an analysis run in tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

RunJobs = Callable[[], int]


def new_case(api: TestClient, name: str = "Analysis") -> str:
    response = api.post("/api/cases", json={"name": name, "analyst_name": "R. Analyst"})
    assert response.status_code == 201, response.text
    return str(response.json()["case_id"])


def upload(api: TestClient, case_id: str, data: bytes, filename: str, **params: Any) -> Any:
    response = api.post(
        f"/api/cases/{case_id}/files", params={"filename": filename, **params}, content=data
    )
    assert response.status_code == 201, response.text
    return response.json()


def analyze(
    api: TestClient, run_jobs: RunJobs, case_id: str, overrides: dict[str, Any] | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run all pending jobs, start a run, finish it; return (run, findings)."""
    run_jobs()
    response = api.post(f"/api/cases/{case_id}/runs", json={"overrides": overrides or {}})
    assert response.status_code == 202, response.text
    run_jobs()
    run = api.get(f"/api/runs/{response.json()['run_id']}").json()
    findings = api.get(f"/api/runs/{run['run_id']}/findings").json()
    return run, findings


def by_rule(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [f for f in findings if f["rule_id"] == rule_id]
